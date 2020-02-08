#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

#include <fstream>///
#include <TCPConn.h>///
#include <string> ///
#include <vector>///

const int HASHLEN = 32;///
const int SALTLEN = 16;///

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;

   bool result = findUser(name, passwd, salt);

   //reads the passwd file to look for existing users
   std::ifstream fileInput;
   int offset;
   std::string line;
   std::string search = name;
   // open file to search
   fileInput.open("passwd");
   if (fileInput.is_open()) {
	   std::cout << "\nOPEN\n";
	   while (getline(fileInput, line)) { 
		   if (line.find(search, 0) != std::string::npos) {
			   result = true;
		   }
	   }
	   fileInput.close();
   }
   else std::cout << "Unable to open file.";

   return result;///returning true means user already exists
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
//bool PasswdMgr::checkPasswd(std::string name, std::string passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   //std::cout << "\nIn checkPasswd\n";///

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   //hashArgon2(passhash, salt, passwd, &salt);

   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(std::string name, std::string passwd) {

	//assigns passwd file and makes sure it can open
	std::ifstream fileIn("passwd");
	if (!fileIn.is_open())
	{
		std::cout << "Failed to open file!\n";
		return 0;
	}

	std::string data;
	std::vector<std::string> myVec;  
	int i = 0;
	//makes vector to search through passwd file
	while (fileIn >> data) 
	{
		myVec.push_back(data);
	}
	//iterates through passwd file to find username & passwd to change
	for (std::string::size_type i = 0; i < myVec.size(); i++) {
		if (myVec[i] == name)
			myVec[i + 1] = passwd;
	}

	
	std::ofstream ofs;
	ofs.open("passwd", std::ofstream::out);
	//changes passwd in file
	for (std::string::size_type i = 0; i < myVec.size(); i++) {
		ofs << myVec[i] << "\n" << myVec[i + 1] << "\n";
		i++;
	}

	ofs.close();

   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!
	//std::cout << "\nIn readUser, name: " << name << "\n";


   return false;//returns true if entry read
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   // Insert your wild code here!
   //std::cout << "\nIn writeUser\n";

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(std::string name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation
   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
	   std::string uname;
      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }
	  
      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
//void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, const char *in_passwd, std::vector<uint8_t> *in_salt) {
void PasswdMgr::hashArgon2(const char* in_passwd)
{
	char saltCharArray[16];
	char hashCharArray[32];
	std::string saltString;
	std::string hashString;

   // Hash those passwords!!!!
	uint8_t hash1[HASHLEN];
	uint8_t salt[SALTLEN];
	//assigns random salt to each user
	for (unsigned int i = 0; i < SALTLEN; i++)
		salt[i] = ((rand() % 93) + 33);	

	uint8_t* pwd = (uint8_t*)strdup(in_passwd);
	uint32_t pwdlen = strlen((char*)pwd);
	uint32_t t_cost = 2;            
	uint32_t m_cost = (1 << 16);      
	uint32_t parallelism = 1;       

	//creates hash using salt from above
	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);

	//opening passwd file and new adding users and password
	std::ofstream ofs;
	ofs.open("passwd", std::ofstream::out | std::ofstream::app);
	ofs << "hash:" << hash1 << "\n" <<"salt:" << salt << "\n";
	ofs.close();
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
	// Add those users!
	srand(time(0));
	//adding users to passwd file
	std::ofstream ofs;
	ofs.open("passwd", std::ofstream::out | std::ofstream::app);
	ofs << name << "\n" << passwd << "\n"; //<< "   " << hash1 << "   " << salt << "\n";
	ofs.close();
	//send passwd to get hashed
	hashArgon2(passwd);

}

