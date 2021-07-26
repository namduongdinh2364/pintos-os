#!/bin/bash

#rm filesys.dsk

echo "Copy echo ELF to filesys.dsk"
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
pintos -p ../../examples/echo -a echo -- -q
echo "pintos run 'echo x'"
