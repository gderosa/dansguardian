//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.
//Written by Daniel Barron (daniel@jadeb//.com) but heavily based on code
//written by Aecio F. Neto (afn@harvest.com.br).
//For support go to http://groups.yahoo.com/group/dansguardian

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "ImageContainer.hpp"

#include <syslog.h>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <limits.h>


// GLOBALS

extern bool is_daemonised;


// IMPLEMENTATION

ImageContainer::ImageContainer()
{
	image = NULL;
	imagelength = 0;
}

ImageContainer::~ImageContainer()
{
	delete[]image;
}

// wipe the loaded image
void ImageContainer::reset()
{
	delete[]image;
	image = NULL;
	mimetype = "";
	imagelength = 0;
}

// send image to client
void ImageContainer::display(Socket * s)
{
#ifdef DGDEBUG
	std::cout << "Displaying custom image file" << std::endl;
	std::cout << "mimetype: " << mimetype << std::endl;
#endif
	(*s).writeString("Content-type: ");
	(*s).writeString(mimetype.toCharArray());
	(*s).writeString("\n\n");
	(*s).writeToSocket(image, imagelength, 0, (*s).getTimeout());
}

// read image from file
bool ImageContainer::read(const char *filename)
{
	String temp;
	temp = (char *) filename;
	temp.toLower();
	if (temp.endsWith(".jpg") || temp.endsWith(".jpeg")
	    || temp.endsWith(".jpe")) {
		mimetype = "image/jpg";
	}
	else if (temp.endsWith("png"))
		mimetype = "image/png";
	else if (temp.endsWith("swf"))
		mimetype = "application/x-shockwave-flash";
	else{
		mimetype = "image/gif";
	}

	std::ifstream imagefile;
	imagefile.open(filename, std::ifstream::binary);
	imagefile.seekg(0, std::ios::end);
	imagelength = imagefile.tellg();
	imagefile.seekg(0, std::ios::beg);

	if (imagelength) {
		if (image != NULL)
			delete[] image;
		image = new char[imagelength + 1];
		imagefile.read(image, imagelength);
		if (!imagefile.good()) {
			if (!is_daemonised)
				std::cerr << "Error reading custom image file: " << filename << std::endl;
			syslog(LOG_ERR, "%s", "Error reading custom image file.");
			return false;
		}
	} else {
		if (!is_daemonised)
			std::cerr << "Error reading custom image file: " << filename << std::endl;
		syslog(LOG_ERR, "%s", "Error reading custom image file.");
		return false;
	}
	imagefile.close();
//    #ifdef DGDEBUG
//      for (long int i = 0; i < imagelength; i++)
//          printf("Image byte content: %x\n", image[i]);
//    #endif
	return true;
}
