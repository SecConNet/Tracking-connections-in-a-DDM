# Tracking container network connections in a DDM


This file saves the number of access to the containers in a reigister by using a unique id as the index of the registers. In this way we can measure the number of access to a specific container that includes an asset and the number of access from a specific domain. 

The file "access_tracking.p4" also saves the information of the behaviour of access to a specific asset. It saves the idle and active time of access to a specific asset by using registers. In below code the maximum idle time is saved in a register:
```
      time_interval.read ( t_max, (bit<32>) hdr.tcp.dstPort);
      packet_last_time.read (t_last, (bit<32>) hdr.tcp.dstPort);
      if (t_last != 0 )
      {
	      t_difference = stdmeta.ingress_global_timestamp - t_last ;
	      if (t_difference > t_max ) 
        	{
		      time_interval.write ((bit<32>) hdr.tcp.dstPort, t_difference);
        	}
      }

```

The information saved in the registers are read priodically by controller of the switch that is programmed by this file.

The file "" is for detecting the highload on the system and sending a notification to the controller if the load is higher that what is determined in the switch. In the blow code the notification is sent to the controller:

```
	time_to_complete = stdmeta.ingress_global_timestamp - t_syn;
	if (time_to_complete > max_time_to_complete )
	{
 	     long_connections.read(connections, (bit<32>)hdr.tcp.dstPort);
	     connections = connections + 1;
	     long_connections.write((bit<32>) hdr.tcp.dstPort, connections);
	 }
         if (connections > max_long_connection )
	 {
	     stdmeta.egress_spec = CPU_PORT;
             hdr.packet_in.setValid();
	 }
```
