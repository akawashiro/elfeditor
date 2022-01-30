#! /bin/bash -eux

./elfeditor dump tests/hello hello.json
./elfeditor apply tests/hello hello.no.edit hello.json
diff tests/hello hello.no.edit
