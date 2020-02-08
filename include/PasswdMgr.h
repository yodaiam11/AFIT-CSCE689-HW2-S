#ifndef PASSWDMGR_H
#define PASSWDMGR_H

#include <string>
#include <stdexcept>
#include "FileDesc.h"

/****************************************************************************************
 * PasswdMgr - Manages user authentication through a file
 *
 ****************************************************************************************/

class PasswdMgr {
   public:
      PasswdMgr(const char *pwd_file);
      ~PasswdMgr();

      bool checkUser(const char *name);
      bool checkPasswd(const char* name, const char* newpassd);
      bool changePasswd(std::string name, std::string newpassdd);
   
      void addUser(const char *name, const char *passwd);

	  void hashArgon2(const char* passwd);

   private:
      bool findUser(std::string name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);
      bool readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);
      int writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);

      std::string _pwd_file;
};

#endif
