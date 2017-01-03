
distribute: server.c
	gcc -O1 -DPIN1=\"123456\" -DPIN2=\"123456\" -DFLAG1=\"33C3_NOT_FLAG_1\" -DFLAG2=\"33C3_NOT_FLAG_2\" -DFLAG3=\"33C3_NOT_FLAG_3\" -o server server.c -lssl -lcrypto

release: server.c
	gcc -O1 -DPIN1=\"768305\" -DPIN2=\"482633\" -DFLAG1=\"33C3_s1impl3_4sync_s3rver\" -DFLAG2=\"33C3_sh0rt_p4ssc0de_1s_shOrt\" -DFLAG3=\"33C3_PKCS_7_1s_h4rd_app4r3ntly\" -o server server.c -lssl -lcrypto
