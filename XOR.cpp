#include <iostream>

using std::string;

string encryptDecrypt(string toEncrypt) {
	char key[32] = { 'N', 'H', 'J', 'K', 'R', 'E', 'J', 'S', 'W', 'Z', 'B', 'G', 'X', 'W', 'O', 'P', 'I', 'N', 'C', 'A', 'U', 'D', 'D', 'Y', 'L', 'V', 'H', 'A', 'J', 'X', 'W', 'S' }; //Any chars will work, in an array of any size
	string output = toEncrypt;

	for (int i = 0; i < toEncrypt.size(); i++)
		output[i] = toEncrypt[i] ^ key[i % (sizeof(key) / sizeof(char))];

	return output;
}