#!/bin/bash

found_js=false

for file in *.svg; do
    [ -f "$file" ] || continue
    
    if grep -i -E 'script' "$file" > /dev/null; then
        echo "Javascript found in: $file"
        found_js=true
    fi
done

if [ "$found_js" = true ]; then
    exit 1
else
    echo "No script tags found in SVG files"
    exit 0
fi