# Software-Defined-Networks-
Mininet, RYU, OpenFLow v-1.3, ECMP, Load Balancing, Reactive Flows 


Task 1:

Limit the flow table size at top-level switches

![alt text](https://github.com/Samruddhi1995/Software-Defined-Networks-/blob/master/LimitSizeOfFlowTable.PNG)
      

Task 2 :

![alt text](https://github.com/Samruddhi1995/Software-Defined-Networks-/blob/master/ReactiveFLow.PNG)


Controller (reactive_controller.py) adds reactive flows  when a new TCP flow arrives, (srcIP, dstIP, srcPort, dstPort).
Switch S4 and S5 forwards the first packet to controller and controller sets up a path S4-S1-S5 for both directions.
One new flow inserts two new rules in all the switches in the data path.

