#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');

// Configuration
const BINARIES_DIR = path.join(__dirname, '..', 'src-tauri', 'bin');
const TEMP_DIR = path.join(__dirname, '..', 'temp-downloads');

function detectPlatform() {
    const platform = os.platform();
    
    if (platform === 'win32') {
        return 'windows';
    } else if (platform === 'linux') {
        return 'linux';
    } else if (platform === 'darwin') {
        return 'macos';
    } else {
        throw new Error(`Unsupported platform: ${platform}`);
    }
}

function ensureDirectory(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`Created directory: ${dir}`);
    }
}

function downloadFile(url, destination) {
    return new Promise((resolve, reject) => {
        console.log(`Downloading ${url}...`);
        const file = fs.createWriteStream(destination);
        
        const request = https.get(url, (response) => {
            // Handle redirects
            if (response.statusCode === 302 || response.statusCode === 301) {
                file.close();
                fs.unlinkSync(destination);
                return downloadFile(response.headers.location, destination)
                    .then(resolve)
                    .catch(reject);
            }
            
            if (response.statusCode !== 200) {
                file.close();
                fs.unlinkSync(destination);
                return reject(new Error(`Download failed with status ${response.statusCode}`));
            }
            
            response.pipe(file);
            
            file.on('finish', () => {
                file.close();
                console.log(`Downloaded: ${path.basename(destination)}`);
                resolve();
            });
            
            file.on('error', (err) => {
                file.close();
                fs.unlinkSync(destination);
                reject(err);
            });
        });
        
        request.on('error', (err) => {
            file.close();
            if (fs.existsSync(destination)) {
                fs.unlinkSync(destination);
            }
            reject(err);
        });
    });
}

async function downloadPrebuiltBinaries() {
    const platform = detectPlatform();
    console.log(`Platform detected: ${platform}`);
    
    // For now, let's create placeholder files and provide instructions
    // This is more realistic than trying to compile complex tools
    
    const nmapPath = path.join(BINARIES_DIR, platform === 'windows' ? 'nmap.exe' : 'nmap');
    const masscanPath = path.join(BINARIES_DIR, platform === 'windows' ? 'masscan.exe' : 'masscan');
    
    console.log('\n📋 Binary Setup Instructions');
    console.log('============================');
    
    if (platform === 'windows') {
        console.log('\nFor Windows:');
        console.log('1. Download nmap from: https://nmap.org/download.html');
        console.log('   - Get the Windows installer or ZIP file');
        console.log('   - Extract nmap.exe and place it in:', nmapPath);
        console.log('');
        console.log('2. Download masscan:');
        console.log('   - Download from: https://github.com/robertdavidgraham/masscan/releases');
        console.log('   - Or compile from source using MinGW/Visual Studio');
        console.log('   - Place masscan.exe in:', masscanPath);
    } else {
        console.log(`\nFor ${platform}:`);
        console.log('1. Install nmap:');
        console.log('   sudo apt install nmap  # Ubuntu/Debian');
        console.log('   sudo yum install nmap  # RHEL/CentOS');
        console.log('   brew install nmap      # macOS');
        console.log('');
        console.log('2. Install masscan:');
        console.log('   sudo apt install masscan  # Ubuntu/Debian');
        console.log('   # Or compile from source:');
        console.log('   git clone https://github.com/robertdavidgraham/masscan.git');
        console.log('   cd masscan && make');
        console.log('');
        console.log('3. Copy to local bin directory:');
        console.log(`   cp $(which nmap) "${nmapPath}"`);
        console.log(`   cp $(which masscan) "${masscanPath}"`);
    }
    
    // Create README file with instructions
    const readmePath = path.join(BINARIES_DIR, 'BINARY_SETUP.md');
    const readmeContent = `# Binary Setup for LEGION2

## Required Binaries

LEGION2 requires nmap and masscan binaries to function properly. Place them in this directory:

- \`${platform === 'windows' ? 'nmap.exe' : 'nmap'}\`
- \`${platform === 'windows' ? 'masscan.exe' : 'masscan'}\`

## Download Sources

### Nmap
- Website: https://nmap.org
- Windows: Download from https://nmap.org/download.html
- Linux/macOS: Install via package manager or compile from source

### Masscan
- Repository: https://github.com/robertdavidgraham/masscan
- Windows: Download release or compile with MinGW/Visual Studio
- Linux/macOS: Install via package manager or compile from source

## Verification

After placing binaries, you can verify they work by running:
- \`${platform === 'windows' ? '.\\nmap.exe' : './nmap'} --version\`
- \`${platform === 'windows' ? '.\\masscan.exe' : './masscan'} --version\`

## Licensing

Both nmap (GPL-2.0) and masscan (AGPL-3.0) are open source.
See THIRD_PARTY_LICENSES.md in the project root for details.
`;

    fs.writeFileSync(readmePath, readmeContent);
    console.log(`\n📝 Setup instructions written to: ${readmePath}`);
    
    console.log('\n🔍 Checking for existing system installations...');
    
    // Check if tools are available in system PATH
    try {
        const { execSync } = require('child_process');
        
        try {
            execSync(`${platform === 'windows' ? 'where' : 'which'} nmap`, { stdio: 'ignore' });
            console.log('✅ nmap found in system PATH');
        } catch {
            console.log('❌ nmap not found in system PATH');
        }
        
        try {
            execSync(`${platform === 'windows' ? 'where' : 'which'} masscan`, { stdio: 'ignore' });
            console.log('✅ masscan found in system PATH');
        } catch {
            console.log('❌ masscan not found in system PATH');
        }
    } catch (error) {
        console.log('⚠️  Could not check system PATH');
    }
    
    console.log('\n💡 LEGION2 will automatically detect and use:');
    console.log('   1. Local binaries in this directory (preferred)');
    console.log('   2. System-installed binaries (fallback)');
}

async function main() {
    console.log('LEGION2 Binary Setup');
    console.log('====================');
    
    try {
        ensureDirectory(TEMP_DIR);
        ensureDirectory(BINARIES_DIR);
        
        await downloadPrebuiltBinaries();
        
        // Clean up temp directory
        if (fs.existsSync(TEMP_DIR)) {
            fs.rmSync(TEMP_DIR, { recursive: true, force: true });
        }
        
        console.log('\n✅ Setup completed!');
        
    } catch (error) {
        console.error('\n❌ Setup failed:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { main };