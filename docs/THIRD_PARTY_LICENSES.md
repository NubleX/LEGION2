# Third Party Software Licenses

LEGION2 currently invokes the following third-party scanning tools as external dependencies. We are grateful to the developers of these tools for making them available under open source licenses.

> **Roadmap:** Native Rust replacements for nmap and masscan are in development (`nmap_stream.rs`, `masscan_stream.rs`). Once complete, LEGION2 will no longer bundle or depend on GPL-2.0/AGPL-3.0 binaries for core scanning.

## Nmap Network Mapper

**Version**: 7.94+ (system package or official binary)  
**License**: GPL-2.0 (GNU General Public License v2.0)  
**Website**: https://nmap.org  
**Source Code**: https://github.com/nmap/nmap  

**Description**: Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing. LEGION2 orchestrates nmap for host discovery, service detection, and NSE scripts.

**License Text**: The full text of the GPL-2.0 license can be found at:
- https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
- https://github.com/nmap/nmap/blob/master/LICENSE

**Copyright Notice**:
```
Nmap is (C) 1996-2023 Insecure.Com LLC (fyodor@nmap.org).
```

**Modifications**: LEGION2 does not modify nmap source code. It invokes the nmap binary installed on the host system or obtained from official sources.

## Masscan

**Version**: 1.3.2+ (system package or official binary)  
**License**: AGPL-3.0 (GNU Affero General Public License v3.0)  
**Website**: https://github.com/robertdavidgraham/masscan  
**Source Code**: https://github.com/robertdavidgraham/masscan  

**Description**: Internet-scale port scanner used by LEGION2 for high-rate port sweeps in the Massmap pipeline.

**License Text**: The full text of the AGPL-3.0 license can be found at:
- https://www.gnu.org/licenses/agpl-3.0.html
- https://github.com/robertdavidgraham/masscan/blob/master/LICENSE

**Copyright Notice**:
```
Copyright (c) 2013 Robert David Graham
```

**Modifications**: LEGION2 does not modify masscan source code. It invokes the masscan binary installed on the host system or obtained from official releases.

## License Compliance

### GPL-2.0 Compliance (Nmap)
- **Source Code Availability**: https://github.com/nmap/nmap
- **Distribution Rights**: Any redistribution of nmap binaries must comply with GPL-2.0
- **Modifications**: No modifications to nmap source by LEGION2
- **License Notice**: This notice informs users of their rights under GPL-2.0

### AGPL-3.0 Compliance (Masscan)
- **Source Code Availability**: https://github.com/robertdavidgraham/masscan
- **Network Use Clause**: Under AGPL-3.0, offering masscan as a network service may require source disclosure to users
- **Distribution Rights**: Any redistribution of masscan binaries must comply with AGPL-3.0
- **Modifications**: No modifications to masscan source by LEGION2
- **License Notice**: This notice informs users of their rights under AGPL-3.0

## User Rights and Obligations

### For Nmap (GPL-2.0)
Users have the right to use, study, modify, and distribute the software. Users must include the license and copyright notice and provide source code when distributing.

### For Masscan (AGPL-3.0)
Users have the right to use, study, modify, and distribute the software. Users must include the license and copyright notice, provide source code when distributing or offering network services, and use the same license for derivative works.

## Additional Information

### Current Integration Model
LEGION2 invokes nmap and masscan as **external system binaries** (documented in installation instructions). LEGION2 does not ship modified copies inside the application bundle unless explicitly noted in release artifacts.

### Source Code Access
- **Nmap**: https://github.com/nmap/nmap or https://nmap.org/download.html
- **Masscan**: https://github.com/robertdavidgraham/masscan

### Contact Information
- For nmap: fyodor@nmap.org
- For masscan: https://github.com/robertdavidgraham/masscan/issues
- For LEGION2: https://github.com/NubleX/LEGION2/issues

## Acknowledgments

We thank the developers and contributors of nmap and masscan for creating these powerful network scanning tools. Their work enables security professionals worldwide to better understand and secure their networks.

## Disclaimer

LEGION2 is a separate project and is not affiliated with, endorsed by, or connected to the nmap or masscan projects. The inclusion of these tools does not imply any official relationship or endorsement.

---

*Last Updated: June 2026*  
*LEGION2 Version: 0.4.0*
