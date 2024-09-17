echo
echo "Script to run PA - 01"
echo "By: Conor McFadden and Patrick Dodds"
echo

# Removes all files required
rm -f genkey key.bin iv.bin
rm -f amal/amal amal/logAmal.txt amal/ciphertext.bin
rm -f basim/logBasim.txt basim/decryptedtext.bin
rm -f bunny amal/key.bin amal/iv.bin basim/key.bin basim/iv.bin
rm -f 4 6 dispatcher bunny.decr

# Creates symbolic link
ln -s ../bunny.mp4 bunny

# Builds the executibles
gcc genkey.c -o genkey -lcrypto
gcc amal/amal.c myCrypto.c -o amal/amal -lcrypto
# gcc basim/basim.c myCrypto.c -o basim/basim -lcrypto
gcc dispatcher.c wrappers.c -o dispatcher -lcrypto

# Generates key
echo
echo "Generating Key/IV:"
./genkey

# Hexdumps key
echo
echo "Hexdump key.bin"
echo "====================="
hexdump -C key.bin

# Hexdumps iv
echo
echo "Hexdump iv.bin"
echo "====================="
hexdump -C iv.bin

# Creates amal's symbolic links to key.bin and iv.bin
cd amal
ln -s ../key.bin key.bin
ln -s ../iv.bin  iv.bin

cd ../basim
# Creates basim's symbolic links to key.bin and iv.bin
ln -s ../key.bin key.bin
ln -s ../iv.bin iv.bin


cd ../
# Executes dispatcher
echo
echo "Starting Dispatcher Process..."
echo 
./dispatcher

# Amal's log print
echo
echo "==== Amal's LOG ======"
cat amal/logAmal.txt

# # Basim's log print
# echo
# echo "==== Basim's LOG ======"
# cat basim/logBasim.txt

diff -s ../bunny.mp4 bunny.decr