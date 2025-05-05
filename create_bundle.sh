#!/bin/bash

# Check if a version argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

# First, you do need to run './gradlew publish' to generate the artifacts.
# I can't publish via API, but I can create a bundle for manual upload.

VERSION=$1
# Use this script as a stop gap for manual uploading
mkdir -p io/github/andrewquijano/ciphercraft/$VERSION
cp build/libs/* io/github/andrewquijano/ciphercraft/$VERSION/
cp build/publications/mavenJava/pom-default.xml io/github/andrewquijano/ciphercraft/$VERSION/ciphercraft-$VERSION.pom
cp build/publications/mavenJava/pom-default.xml.asc io/github/andrewquijano/ciphercraft/$VERSION/ciphercraft-$VERSION.pom.asc

# Loop through all files in the specified directory
for file in io/github/andrewquijano/ciphercraft/$VERSION/*; do
  # Print the file being checked
  echo "Processing file: $file"

  # Skip files ending with .asc
  if [[ -f "$file" && ! "$file" =~ \.asc$ ]]; then
    echo "Generating hashes for: $file"

    # Generate SHA1 checksum
    sha1sum "$file" | awk '{print $1}' > "${file}.sha1"

    # Generate MD5 checksum
    md5sum "$file" | awk '{print $1}' > "${file}.md5"
  else
    echo "Skipping file: $file"
  fi
done

zip -r bundle.zip io/