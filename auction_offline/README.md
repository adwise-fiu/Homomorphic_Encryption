# Auction offline

Create your offline version (uses only localhost) to run the comparison protocols. This is the same as the integration test in the JUnit test in the tests directory.

```
# Compile and Link with Library
javac -cp "crypto.jar:." -sourcepath "." OfflineAuction.java

# Run the program
java -cp "crypto.jar:." OfflineAuction
```
