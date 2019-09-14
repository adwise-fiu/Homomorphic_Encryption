#!/bin/bash

# Only run from Root!
javac -cp ".:../libs/bcprov-ext-jdk15on-162.jar" -sourcepath "." Main.java 

echo "Java compilation complete!"

# Run the program
java -cp ".:../libs/bcprov-ext-jdk15on-162.jar:../bin" Main $1
