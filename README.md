# Inside MS Teams

## Journal de bord
- ...
- 27/12/2025 : J'ai recommencé pour extraire la clé privée en exécutant curl. Il faut avoir la version sous OpenSSL, qui n'est pas la version par défaut sous Windows. 
- 28/12/2025 : Adaptation du tracebuilder et de l'analyseur pour qu'il prenne en compte les spécificités de Windows. Mais il y a un problème qui génère l'erreur : curl: (35) Send failure: Connection was aborted. Donc curl n'arrive jamais au bout de son exécution et ne renvoie pas la page. Par conséquent je n'avais pas de candidat lorsque je faisais l'analyse.
- 01/01/2026 : J'ai d'abord pensé à augmenter le --max-time et --connection-time de curl mais cela ne résolvait pas le problème. J'ai par conséquent ajouté un filtre et changé des bouts de l'implémentation de tracebuilder sans pour autant changer la logique du code. J'ai toujours l'erreur.
- 02/01/2026 : J'arrive quand même à trouver un candidat en faisant l'analyse sur la trace collectée (3.63 GB). Je n'avais pas la lib et le delta initialement (None, Inf), mais avec quelques modifications sur io_utils.py , on les retrouve bien dans libssl