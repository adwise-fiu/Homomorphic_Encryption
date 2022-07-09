#!/bin/bash

# Create Bob and Alice
javac -cp crypto.jar test_alice.java
javac -cp crypto.jar test_bob.java

# Create Bob to run in background
java -cp ".:crypto.jar" test_bob &
echo "Bob is ready. Sleep a minute to give time for Alice to Run"
sleep 1m
java -cp ".:crypto.jar" test_alice
