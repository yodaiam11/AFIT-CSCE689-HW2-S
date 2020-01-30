#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include "TCPConn.h"
#include "strfuncts.h"

#include <fstream>
// The filename/path of the password file
const char pwdfilename[] = "passwd";

TCPConn::TCPConn(){ // LogMgr &server_log):_server_log(server_log) {

}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

	// Skipping this for now
	_status = s_username;
	//std::cout << "\nIn startAUthentication\n";///
   //_connfd.writeFD("Username: ");
	if (_status == s_menu) {
		_connfd.writeFD("\nPlease enter a number from the menu\n\nType menu to see the options available\n\nUser Input: ");
	} else if (_status == s_username) {
		_connfd.writeFD("Username: ");
	} else if (_status == s_changepwd) {
		_connfd.writeFD("\nPlease enter your old password: ");
	}

}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {
	
   //std::cout << "\nIn Conn handleConnection\n";///

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
			 //std::cout << "\nIn s_userman\n";///
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();

            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Insert your mind-blowing code here
	//std::cout << "\nIn getUsername\n";
	if (!_connfd.hasData())
		return;
	std::string cmd;

	if (!getUserInput(cmd))
		return;
	lower(cmd);

	std::cout << "\nIn getUsername cmd: " << cmd << "\n";

	//reads the passwd file to look for existing users
	bool exit = true;
	std::ifstream fileInput;
	int offset;
	std::string line;
	std::string search = cmd; // test variable to search in file
	// open file to search
	fileInput.open("passwd");
	if (fileInput.is_open()) {
		//std::cout << "\nOPEN\n";
		//unsigned int curLine = 0;
		while (getline(fileInput, line)) {
			//curLine++;
			if (line.find(search, 0) != std::string::npos) {
				//std::cout << "found: " << search << "line: " << curLine << "\n";
				std::cout << "User found\n";
				//_status = s_passwd;
				_username = cmd;
				_connfd.writeFD("\nPlease enter your password: \n");
				exit = false;
			}
		}
		fileInput.close();
		if (exit == true) {
			_connfd.writeFD("User not authorized, goodbye!\n");
			disconnect();
		}
	}
	else std::cout << "Unable to open file.";

	_status = s_passwd;
	

	//if (cmd.compare("ryan") == 0) {
		//_connfd.writeFD("\nPlease enter your new password: \n");
		//sendCheckPasswd();
	//}
	//else if (cmd.compare("new password") == 0) {
		//_connfd.writeFD("\nPlease enter your new password: \n");
		//take input and then tell them to enter it again
		//_connfd.writeFD("\nNot the correct password, Please try again: \n");
		//compare the two passwords
		//sendStorePasswd();

	//}
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Insert your astounding code here
	//std::cout << "\nIn getPasswd\n";
	//_connfd.writeFD("\nPlease enter your password: \n");
	bool check = false;
	//int count = 0;

	while (check == false) {
		if (!_connfd.hasData())
			return;
		std::string cmd;

		if (!getUserInput(cmd))
			return;
		lower(cmd);
		//std::cout << "\n_username: " << _username;

		//reads the passwd file to look for users passwords
		bool exit = true;
		std::ifstream fileInput;
		int offset;
		std::string line;
		std::string passsearch = _username + "   " + cmd; // test variable to search in file

		// open file to search
		fileInput.open("passwd");
		if (fileInput.is_open()) {
			std::cout << "\nOPEN\n";
			while (getline(fileInput, line)) { 
				//curLine++;
				//std::cout << "\npasssearch: " << passsearch;
				if (line.find(passsearch, 0) != std::string::npos) {
					//std::cout << "found: " << search << "line: " << curLine << "\n";
					std::cout << "\npassword found\n";
					//_status = s_passwd;
					exit = false;
					check = true;
					count = 3;
				}
			}
			count ++;
			fileInput.close();
			if (count == 1) {
				std::cout << "count: " << count << "\n";
				_connfd.writeFD("\nPlease re-enter your password: \n");
				//count ++;
			}
			if (exit == true && count == 2) {
				_connfd.writeFD("Not the correct password, goodbye!\n");
				disconnect();
			}
		}
		else std::cout << "Unable to open file.";
	}

	_connfd.writeFD("\nPlease enter a command from the menu\n\nType menu to see the options available\n\nUser Input: ");
	_status = s_menu;
}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   // Insert your amazing code here
	if (!_connfd.hasData())
		return;
	std::string cmd;
	if (!getUserInput(cmd))
		return;
	lower(cmd);

	if (cmd.compare("password") == 0) {
		_connfd.writeFD("\nPlease enter your new password: \n");
		//sendCheckPasswd();
	}
	else if (cmd.compare("new password") == 0) {
		_connfd.writeFD("\nPlease enter your new password: \n");
		//take input and then tell them to enter it again
		//_connfd.writeFD("\nNot the correct password, Please try again: \n");
		//compare the two passwords
		//sendStorePasswd();

	} else {
		_connfd.writeFD("\nNot the correct password, Please try again: \n");
	}
}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   //std::cout << "\nIn getUserInput\n";///

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   //I was not lazy and used my own outputs!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello from the other side...\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "Menu 1\nThe weather is going to be hot, cold, rain, snow, cloudy, or sunny combination of these.\n\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("Menu 2\nWhat do you call cheese that's not yours?\nNacho cheese\n\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("Menu 3\nIt's a beautiful day in the neighborhood.\n\n");
   } else if (cmd.compare("4") == 0) {
	   _connfd.writeFD("Menu 4\nIt's the song that never ends, it goes on and on my friends...\n\n");
   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("Menu 5\nThis is your weekly test of the Server/Client connection...\n\n");
   } else {
      msg = "error, not a readable command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Made this my own!
   menustr += "Allowable commands: \n";
   menustr += "1 - Weather\n";
   menustr += "2 - Joke\n";
   menustr += "3 - Mr. Rodgers\n";
   menustr += "4 - Song\n";
   menustr += "5 - Test\n";
   menustr += "hello - greeting message\n";
   menustr += "passwd - change your password\n";
   menustr += "exit - to disconnect\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
	_inputbuf = buf;
	std::cout << "\nIP Address: " << buf << "\n";
   return _connfd.getIPAddrStr(buf);
}

//checks if ip address of client is on whitelist///
bool TCPConn::checkWhitelist(std::string _ipaddress) {
	std::cout << "\ncheckWhitelist ipaddress: " << _ipaddress << "\n";
	//whiteList == true;

	//reads the passwd file to look for existing users
	bool ip = true;
	std::ifstream fileInput;
	int offset;
	std::string line;
	std::string search = _ipaddress; // test variable to search in file
	// open file to search
	fileInput.open("whitelist");
	if (fileInput.is_open()) {
		while (getline(fileInput, line)) {
			if (line.find(search, 0) != std::string::npos) {
				std::cout << "ipaddress found\n";
				ip = false;
				return true;
			}
		}
		fileInput.close();
		if (ip == true) {
			return false;
		}
	}
	else std::cout << "Unable to open file.";
}


