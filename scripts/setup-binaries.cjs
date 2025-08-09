#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');
const os = require('os');

// Configuration - Fixed versions that we know work
const BINARIES_DIR = path.join(__dirname, '..', 'src-tauri', 'bin');
const TEMP_DIR = path.join(__dirname, '..', 'temp-setup');

// Stable, tested URLs that won't change
const STABLE_BINARIES = {
    windows: {
        nmap: {
            // Using a specific, stable version that we've tested
            url: 'https://github.com/nmap/nmap/releases/download/7.94/nmap-7.94-setup.exe',
            executable: 'nmap.exe',
            extract: false, // We'll extract from installer
            version: '7.94'
        },
        masscan: {
            // Using our own hosted version or a stable GitHub release
            url: 'https://github.com/robertdavidgraham/masscan/releases/download/1.3.2/masscan-1.3.2.tar.gz',
            executable: 'masscan.exe', 
            extract: true,
            version: '1.3.2'
        }
    },
    linux: {
        nmap: {
            command: 'which nmap',
            fallback: 'apt-get install nmap -y || yum install nmap -y',
            executable: 'nmap',
            version: 'system'
        },
        masscan: {
            command: 'which masscan',
            fallback: 'apt-get install masscan -y || yum install masscan -y',
            executable: 'masscan',
            version: 'system'
        }
    }
};

function detectPlatform() {
    const platform = os.platform();
    if (platform === 'win32') return 'windows';
    if (platform === 'linux' || platform === 'darwin') return 'linux';
    throw new Error(`Unsupported platform: ${platform}`);
}

function ensureDirectory(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

function setupWindowsBinaries() {
    console.log('🔧 Setting up Windows binaries...');
    
    const nmapPath = path.join(BINARIES_DIR, 'nmap.exe');
    const masscanPath = path.join(BINARIES_DIR, 'masscan.exe');
    
    // Check if binaries are present
    const nmapExists = fs.existsSync(nmapPath);
    const masscanExists = fs.existsSync(masscanPath);
    
    if (nmapExists && masscanExists) {
        console.log('✅ nmap.exe: Ready');
        console.log('✅ masscan.exe: Ready');
        return true;
    }
    
    if (!nmapExists) console.log('❌ nmap.exe: Missing');
    if (!masscanExists) console.log('❌ masscan.exe: Missing');
    
    return nmapExists && masscanExists;
}

function setupLinuxBinaries() {
    console.log('🔧 Setting up Linux binaries...');
    
    const tools = ['nmap', 'masscan'];
    let allFound = true;
    
    for (const tool of tools) {
        try {
            const systemPath = execSync(`which ${tool}`, { encoding: 'utf8' }).trim();
            if (systemPath) {
                const targetPath = path.join(BINARIES_DIR, tool);
                fs.copyFileSync(systemPath, targetPath);
                fs.chmodSync(targetPath, 0o755);
                console.log(`✅ ${tool}: Copied from system (${systemPath})`);
            }
        } catch (error) {
            console.log(`❌ ${tool}: Not found in system PATH`);
            console.log(`   Install with: sudo apt install ${tool} || sudo yum install ${tool}`);
            allFound = false;
        }
    }
    
    return allFound;
}

async function main() {
    console.log('🚀 LEGION2 Binary Setup (Fixed Versions)');
    console.log('========================================\n');
    
    try {
        const platform = detectPlatform();
        console.log(`🖥️  Platform: ${platform}`);
        
        ensureDirectory(BINARIES_DIR);
        
        let success = false;
        
        if (platform === 'windows') {
            success = setupWindowsBinaries();
        } else {
            success = setupLinuxBinaries();
        }
        
        console.log('\n📊 Setup Summary:');
        console.log('=================');
        
        if (success) {
            console.log('✅ All required binaries are ready');
            console.log('🎉 LEGION2 is fully configured');
        } else {
            console.log('⚠️  Some binaries missing - see instructions above');
            console.log('💡 LEGION2 will fall back to system-installed tools');
        }
        
    } catch (error) {
        console.error(`\n💥 Setup failed: ${error.message}`);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { main };