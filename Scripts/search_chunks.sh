#!/bin/bash
# Script to manually search for secret chunks in trace.binary
# Helps understand how the analyzer matches secrets

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

KEYLOG="${1:-data/key.log}"
TRACE="${2:-data/log/trace.binary}"
CHUNK_SIZE=8  # bytes (16 hex characters)
RESULTS_FILE=$(mktemp)

# Cleanup on exit
trap "rm -f $RESULTS_FILE" EXIT

echo -e "${BLUE}=== Secret Chunk Hunter ===${NC}\n"

# Extract secret from key.log (already just the hex string, 96 chars)
echo -e "${YELLOW}Step 1: Extracting secret from $KEYLOG${NC}"
secret=$(cat "$KEYLOG" | tr -d '\n\r\t ')
secret_bytes=$((${#secret} / 2))
echo "Secret: ${secret:0:64}..."
echo "Total bytes: $secret_bytes"
echo ""

# Function to convert chunk to hexdump format (16-bit words, little-endian)
# Example: 50154774fe815d56 -> "1550 4774 81fe 565d"
chunk_to_hexdump_format() {
    local hex="$1"
    local result=""
    
    # Process each pair of bytes (4 hex chars = 1 word = 2 bytes)
    for ((i=0; i<${#hex}; i+=4)); do
        local byte1="${hex:i:2}"
        local byte2="${hex:i+2:2}"
        # Reverse the two bytes for little-endian
        local word="${byte2}${byte1}"
        result="${result}${word} "
    done
    
    # Remove trailing space
    echo "${result% }"
}

# Function to search in trace
search_chunk() {
    local chunk_num=$1
    local chunk_hex=$2
    local chunk_hexdump=$3
    
    echo -e "${GREEN}Chunk #$chunk_num (bytes $((chunk_num * CHUNK_SIZE))-$((chunk_num * CHUNK_SIZE + CHUNK_SIZE - 1))):${NC}"
    echo "  Original:      $chunk_hex"
    echo "  Hexdump format: $chunk_hexdump"
    
    # Search in hexdump using hexdump
    local matches=$(hexdump "$TRACE" 2>/dev/null | grep -i "$chunk_hexdump" | head -n 20)
    
    if [ -n "$matches" ]; then
        echo -e "  ${RED}FOUND in trace:${NC}"
        echo "$matches" | while read line; do
            # Parse offset to calculate fragment number
            offset=$(echo "$line" | awk '{print $1}')
            offset_dec=$((16#$offset))
            fragment_num=$((offset_dec / 64))
            byte_in_frag=$((offset_dec % 64))
            
            # Extract RIP from the trace at this fragment
            rip_offset=$((fragment_num * 64))
            rip=$(xxd -s $rip_offset -l 8 -p "$TRACE" 2>/dev/null | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\8\7\6\5\4\3\2\1/')
            
            # Determine which register/memory
            if [ $byte_in_frag -lt 8 ]; then
                location="RIP"
            elif [ $byte_in_frag -lt 16 ]; then
                location="RAX"
            elif [ $byte_in_frag -lt 24 ]; then
                location="RSI"
            elif [ $byte_in_frag -lt 32 ]; then
                location="RDI"
            else
                mem_offset=$((byte_in_frag - 32))
                location="MEMORY[$mem_offset]"
            fi
            
            echo "    Frag #$fragment_num, RIP: 0x$rip, in $location"
            
            # Save to results file: chunk_num|rip|location|fragment_num
            echo "$chunk_num|$rip|$location|$fragment_num" >> "$RESULTS_FILE"
        done
    else
        echo "  Not found"
    fi
    echo ""
}

# Split secret into 8-byte chunks and search
echo -e "${YELLOW}Step 2: Searching chunks in $TRACE${NC}\n"

num_chunks=$((secret_bytes / CHUNK_SIZE))
echo "Analyzing $num_chunks chunks of $CHUNK_SIZE bytes each"
echo "================================================"
echo ""

for i in $(seq 0 $((num_chunks - 1))); do
    # Extract chunk (16 hex chars = 8 bytes)
    start=$((i * CHUNK_SIZE * 2))
    chunk_hex="${secret:$start:$((CHUNK_SIZE * 2))}"
    
    # Skip if chunk is all zeros (common, not interesting)
    if [ "$chunk_hex" = "0000000000000000" ]; then
        continue
    fi
    
    # Convert to hexdump format (2 x 16-bit words, little-endian)
    chunk_hexdump=$(chunk_to_hexdump_format "$chunk_hex")
    
    # Search this chunk
    search_chunk $i "$chunk_hex" "$chunk_hexdump"
done

echo -e "${BLUE}=== Candidate Analysis ===${NC}"
echo ""

# Check if we have any results
if [ ! -s "$RESULTS_FILE" ]; then
    echo "No chunks found in trace."
    exit 0
fi

# Count total chunks expected (excluding zeros)
total_chunks=0
for i in $(seq 0 $((num_chunks - 1))); do
    start=$((i * CHUNK_SIZE * 2))
    chunk_hex="${secret:$start:$((CHUNK_SIZE * 2))}"
    if [ "$chunk_hex" != "0000000000000000" ]; then
        total_chunks=$((total_chunks + 1))
    fi
done

echo "Total non-zero chunks in secret: $total_chunks"
echo ""

# Group results by (RIP, register) and find candidates covering all chunks
declare -A candidates
declare -A candidate_chunks
declare -A candidate_fragments

while IFS='|' read -r chunk_num rip location fragment_num; do
    key="${rip}:${location}"
    
    # Track unique chunks covered
    if [ -z "${candidate_chunks[$key]}" ]; then
        candidate_chunks[$key]="$chunk_num"
    else
        # Check if this chunk is already in the list
        if ! echo "${candidate_chunks[$key]}" | grep -q "\b$chunk_num\b"; then
            candidate_chunks[$key]="${candidate_chunks[$key]} $chunk_num"
        fi
    fi
    
    # Count total occurrences
    if [ -z "${candidates[$key]}" ]; then
        candidates[$key]=1
    else
        candidates[$key]=$((${candidates[$key]} + 1))
    fi
    
    # Track fragment numbers
    if [ -z "${candidate_fragments[$key]}" ]; then
        candidate_fragments[$key]="$fragment_num"
    else
        candidate_fragments[$key]="${candidate_fragments[$key]} $fragment_num"
    fi
done < "$RESULTS_FILE"

# Find candidates that cover all chunks
echo -e "${YELLOW}Complete Candidates (covering all chunks):${NC}"
echo ""

best_score=999999
best_candidate=""
best_reg=""
reg_priority_MEMORY32=10
reg_priority_RAX=1
reg_priority_RDI=2
reg_priority_RSI=3

complete_found=false

for key in "${!candidates[@]}"; do
    rip=$(echo "$key" | cut -d: -f1)
    location=$(echo "$key" | cut -d: -f2)
    
    # Count unique chunks covered
    num_covered=$(echo "${candidate_chunks[$key]}" | wc -w)
    
    # Only consider candidates covering all chunks
    if [ $num_covered -eq $total_chunks ]; then
        complete_found=true
        num_occurrences=${candidates[$key]}
        
        # Calculate score based on register priority
        score=100
        case "$location" in
            "RAX") score=$reg_priority_RAX ;;
            "RDI") score=$reg_priority_RDI ;;
            "RSI") score=$reg_priority_RSI ;;
            MEMORY*) score=$reg_priority_MEMORY32 ;;
        esac
        
        echo -e "${GREEN}✓${NC} RIP: 0x$rip, Register: $location"
        echo "  Chunks covered: $num_covered/$total_chunks (100%)"
        echo "  Total occurrences: $num_occurrences"
        echo "  Priority score: $score"
        echo ""
        
        # Track best candidate based on priority score
        if [ $score -lt $best_score ]; then
            best_score=$score
            best_candidate="0x$rip"
            best_reg="$location"
        fi
    fi
done

if [ "$complete_found" = false ]; then
    echo "  None found."
    echo ""
fi

# Show partial candidates
echo -e "${YELLOW}Partial Candidates (incomplete coverage):${NC}"
echo ""

partial_found=false

for key in "${!candidates[@]}"; do
    rip=$(echo "$key" | cut -d: -f1)
    location=$(echo "$key" | cut -d: -f2)
    
    # Count unique chunks covered
    num_covered=$(echo "${candidate_chunks[$key]}" | wc -w)
    
    # Show candidates with partial coverage
    if [ $num_covered -lt $total_chunks ] && [ $num_covered -gt 0 ]; then
        partial_found=true
        num_occurrences=${candidates[$key]}
        coverage_pct=$((num_covered * 100 / total_chunks))
        
        echo -e "${YELLOW}◐${NC} RIP: 0x$rip, Register: $location"
        echo "  Chunks covered: $num_covered/$total_chunks (${coverage_pct}%)"
        echo "  Total occurrences: $num_occurrences"
        echo "  Missing chunks: $((total_chunks - num_covered))"
        echo ""
    fi
done

if [ "$partial_found" = false ]; then
    echo "  None found."
    echo ""
fi

if [ -n "$best_candidate" ]; then
    echo -e "${RED}=== BEST CANDIDATE ===${NC}"
    echo "RIP: $best_candidate"
    echo "Register: $best_reg"
    echo "Priority score: $best_score"
    echo ""
    echo "This is the most likely instruction manipulating the secret!"
else
    echo -e "${YELLOW}No candidate covers all secret chunks.${NC}"
    echo "Partial matches found, but incomplete coverage."
fi

echo -e "${BLUE}=== Search Complete ===${NC}"
echo ""
echo "Note: Each fragment is 64 bytes:"
echo "  Bytes 0-7:   RIP (instruction pointer)"
echo "  Bytes 8-15:  RAX"
echo "  Bytes 16-23: RSI"
echo "  Bytes 24-31: RDI"
echo "  Bytes 32-63: MEMORY (32 bytes)"
