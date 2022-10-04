#pragma once
#include <iostream>

extern std::string encryptDecrypt(std::string toEncrypt);

#define XOR(a) encryptDecrypt(a)