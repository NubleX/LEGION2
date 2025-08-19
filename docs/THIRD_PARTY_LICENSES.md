# Third Party Software Licenses

LEGION2 includes and/or distributes the following third-party software components. We are grateful to the developers of these tools for making them available under open source licenses.

## Nmap Network Mapper

**Version**: 7.94  
**License**: GPL-2.0 (GNU General Public License v2.0)  
**Website**: https://nmap.org  
**Source Code**: https://github.com/nmap/nmap  

**Description**: Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime.

**License Text**: The full text of the GPL-2.0 license can be found at:
- https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
- https://github.com/nmap/nmap/blob/master/LICENSE

**Copyright Notice**:
```
Nmap is (C) 1996-2023 Insecure.Com LLC (fyodor@nmap.org).
```

**Modifications**: LEGION2 distributes unmodified nmap binaries as downloaded from the official sources.

## Masscan

**Version**: 1.3.2  
**License**: AGPL-3.0 (GNU Affero General Public License v3.0)  
**Website**: https://github.com/robertdavidgraham/masscan  
**Source Code**: https://github.com/robertdavidgraham/masscan  

**Description**: This is an Internet-scale port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second, from a single machine.

**License Text**: The full text of the AGPL-3.0 license can be found at:
- https://www.gnu.org/licenses/agpl-3.0.html
- https://github.com/robertdavidgraham/masscan/blob/master/LICENSE

**Copyright Notice**:
```
Copyright (c) 2013 Robert David Graham
```

**Modifications**: LEGION2 may distribute either:
- Unmodified masscan binaries compiled from official source code
- Pre-built binaries obtained from official releases

## License Compliance

### GPL-2.0 Compliance (Nmap)
- **Source Code Availability**: The source code for nmap is available at https://github.com/nmap/nmap
- **Distribution Rights**: We distribute nmap under the terms of GPL-2.0
- **Modifications**: No modifications have been made to the nmap source code
- **License Notice**: This license notice is provided to inform users of their rights under GPL-2.0

### AGPL-3.0 Compliance (Masscan)
- **Source Code Availability**: The source code for masscan is available at https://github.com/robertdavidgraham/masscan
- **Network Use Clause**: Under AGPL-3.0, users who interact with masscan over a network are entitled to receive the source code
- **Distribution Rights**: We distribute masscan under the terms of AGPL-3.0
- **Modifications**: Any modifications (if made) would be clearly documented and source code provided
- **License Notice**: This license notice is provided to inform users of their rights under AGPL-3.0

## User Rights and Obligations

### For Nmap (GPL-2.0)
Users have the right to:
- Use the software for any purpose
- Study and modify the source code
- Distribute copies of the software
- Distribute modified versions

Users must:
- Include the license and copyright notice
- Provide source code when distributing
- Use the same license for derivative works

### For Masscan (AGPL-3.0)
Users have the right to:
- Use the software for any purpose
- Study and modify the source code
- Distribute copies of the software
- Distribute modified versions

Users must:
- Include the license and copyright notice
- Provide source code when distributing or offering network services
- Use the same license for derivative works
- Provide source code to users who access the software over a network

## Additional Information

### Binary Distribution
LEGION2 includes pre-compiled binaries of nmap and masscan for user convenience. These binaries are:
- Downloaded from official sources during the build process
- Distributed in their original, unmodified form
- Subject to the original licenses (GPL-2.0 for nmap, AGPL-3.0 for masscan)

### Source Code Access
Users can obtain the source code for these tools from:
- **Nmap**: https://github.com/nmap/nmap or https://nmap.org/download.html
- **Masscan**: https://github.com/robertdavidgraham/masscan

### Contact Information
If you have questions about the licensing of these third-party components, please contact:
- For nmap: fyodor@nmap.org
- For masscan: https://github.com/robertdavidgraham/masscan/issues
- For LEGION2: https://github.com/yourusername/LEGION2/issues

## Acknowledgments

We thank the developers and contributors of nmap and masscan for creating these powerful network scanning tools and making them available under open source licenses. Their work enables security professionals, network administrators, and researchers worldwide to better understand and secure their networks.

## Disclaimer

LEGION2 is a separate project and is not affiliated with, endorsed by, or connected to the nmap or masscan projects. The inclusion of these tools does not imply any official relationship or endorsement.

---

*Last Updated: January 2025*  
*LEGION2 Version: 0.2.3-alpha*