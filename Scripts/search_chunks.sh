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

KEYLOG="${1:-data/log/sslkeys.log}"
TRACE="${2:-data/log/trace.binary}"
CHUNK_SIZE=4  # bytes (8 hex characters)

echo -e "${BLUE}=== Secret Chunk Hunter ===${NC}\n"

# Extract secret from key.log
echo -e "${YELLOW}Step 1: Extracting secret from $KEYLOG${NC}"
secret=$(awk '{print $3}' "$KEYLOG" | tr -d '\n' | head -c 128)  # First secret, max 64 bytes
secret_bytes=$((${#secret} / 2))
echo "Secret (first 64 bytes): $secret"
echo "Total bytes: $secret_bytes"
echo ""

# Function to reverse bytes for little-endian (with spaces)
reverse_bytes() {
    local hex="$1"
    echo "$hex" | sed 's/../& /g' | awk '{for(i=NF;i>0;i--) printf "%s ",$i}' | sed 's/ $//'
}

# Function to search in trace
search_chunk() {
    local chunk_num=$1
    local chunk_be=$2
    local chunk_le=$3
    
    echo -e "${GREEN}Chunk #$chunk_num (bytes $((chunk_num * CHUNK_SIZE))-$((chunk_num * CHUNK_SIZE + CHUNK_SIZE - 1))):${NC}"
    echo "  Big-endian:    $chunk_be"
    echo "  Little-endian: $chunk_le"
    
    # Search in hexdump using hd (hexdump canonical format)
    # hd format: 00000000  fe f6 a9 a3 f9 7f 00 00  01 00 00 00 00 00 00 00  |................|
    # We search only in the hex part (between offset and ASCII)
    local matches=$(hd "$TRACE" 2>/dev/null | grep -i "$chunk_le" | grep -v "^[0-9a-f]*$chunk_le" | head -n 5)
    
    if [ -n "$matches" ]; then
        echo -e "  ${RED}FOUND in trace:${NC}"
        echo "$matches" | while read line; do
            # Parse offset to calculate fragment number
            offset=$(echo "$line" | awk '{print $1}' | tr -d ':')
            offset_dec=$((16#$offset))
            fragment_num=$((offset_dec / 64))
            byte_in_frag=$((offset_dec % 64))
            
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
                location="MEMORY[${mem_offset}]"
            fi
            
            echo "    Fragment #$fragment_num, offset $offset_dec, in $location"
            echo "    $line"
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
    chunk_be="${secret:$start:$((CHUNK_SIZE * 2))}"
    
    # Skip if chunk is all zeros (common, not interesting)
    if [ "$chunk_be" = "0000000000000000" ]; then
        continue
    fi
    
    # Convert to little-endian
    chunk_le=$(reverse_bytes "$chunk_be")
    
    # Search this chunk
    search_chunk $i "$chunk_be" "$chunk_le"
done

echo -e "${BLUE}=== Search Complete ===${NC}"
echo ""
echo "Note: Each fragment is 64 bytes:"
echo "  Bytes 0-7:   RIP (instruction pointer)"
echo "  Bytes 8-15:  RAX"
echo "  Bytes 16-23: RSI"
echo "  Bytes 24-31: RDI"
echo "  Bytes 32-63: MEMORY (32 bytes)"
