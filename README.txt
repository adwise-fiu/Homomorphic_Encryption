This is a module created from the SST REU 2017 project.

FINISHED 

--Requirements---
JRE 1.8

----Papers------------
Encrypted Integer Division by Thjis Veugen (Division Method, Used Protocol 2 in the Paper)
Improving the DGK comparison protocol by Thjis Veugen
Implemented Protocol 1(In Progress), 2, 3, 4 (In Progress)


--How to export to JAR file to use in other projects--
Phase I - Importing into Eclipse

Phase II - Exporting to JAR file
1- Right-Click Project and select Export
2- Select Java/Java JAR file
3- Be sure you selected the right project! 
4- Be sure to NOT select the default package as that only contains test cases as an example for you to use!
5- Be sure to select to export only generated class files/resources. The source code is here in this repository anyways!
6- Select the path of where JAR file will be exported.
7- SEE AndrewQuijano/SSTREU2017 repository, which shows it uses the jar file from this repository.

-----------STILL A WORK IN PROGRESS----------------

This module contains a function Android and Java support for
- Paillier
- DGK
- DGK Comparison Protocols (NOTE: PROTOCOL 4 IS NOT COMPLETE. May complete later)
- Encrypted Integer Divison.

Context:
In the case of Comparison Protocols. Alice has [[x]] and [[y]], two DGK or Paillier encrypted values. Bob has the DGK and/or Paillier Private Key.
For Division, Alice has [x] and d. Bob has d and Private Key. Alice would obtain [x/d] at the end of division protocol.

By default...the Phone/Server will sort encrypted numbers. Note that comparing two encrypted numbers can take about 1.5 seconds on average.

How to use:
The Phone interface should be pretty straight forward. If you press Alice. Random numbers will be generated and printed. It will connect to Bob 
on the SocialistMillionaire Server and sort the array.

Customizations:
1- Note that Bob DOES close the socket and I/O streams! You may want to avoid this!
2- By default Alice will use MergeSort to sort encrypted arrays. QuickSort is about the same speed.
3- PLEASE BE VERY CAREFUL ABOUT THE SERVER SETTINGS. CURRENTLY IT IS SET TO ALICE MODE AND DGK MODE OFF. This can be changed by changing the code or through the shell!
4- How to use each Protocol...If Alice wants to use a method, Bob must call the correct method for this to work correctly...

Alice			Bob
max/min			Protocol2()
sortArray		Protocol2()
divide			divide()
Protocol2()		Protocol2()
Protocol3() 		Protocol3()

Please feel free to review the SST REU 2017 project which uses this module to get minimum distance and divide encrypted numbers.

-----------Precautions---------------

