#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <list>
#include <vector>
#include "PEhead.h"
using namespace std;
#pragma comment(lib, "Userenv.lib")
class filebinread
{
public :
	std::string filebin;
	void readfilebin(string filepath);
	void RVAtoFOA();
private:
};