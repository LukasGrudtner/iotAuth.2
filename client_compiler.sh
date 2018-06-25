g++ -std=c++17 $1 -o client client.cpp RSA/RSA.cpp RSA/RSAPackage.cpp AES/AES.cpp fdr.cpp utils.cpp iotAuth.cpp Arduino.cpp SHA/sha512.cpp RSA/RSAKeyExchange.cpp  Diffie-Hellman/DiffieHellmanPackage.cpp Diffie-Hellman/DHEncPacket.cpp Diffie-Hellman/DHKeyExchange.cpp RSA/RSAStorage.cpp Diffie-Hellman/DHStorage.cpp time.cpp verbose/verbose_client.cpp -O3 -g
