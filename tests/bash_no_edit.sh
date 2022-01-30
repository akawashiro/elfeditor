#! /bin/bash -eux

./elfeditor dump $(which bash) bash.json
./elfeditor apply $(which bash) bash.no.edit bash.json
diff $(which bash) bash.no.edit
