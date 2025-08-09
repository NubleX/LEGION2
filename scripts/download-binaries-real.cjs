#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');
const os = require('os');

// Configuration
const BINARIES_DIR = path.join(__dirname, '..', 'src-tauri', 'bin');
const TEMP_DIR = path.join(__dirname, '..', 'temp-downloads');

// Real working download URLs
const BINARY_URLS = {
    windows: {
        nmap: {
            // Use a portable nmap version that doesn't require installation
            url: 'https://nmap.org/dist/nmap-7.97-win32.zip',
            fallbacks: [
                'https://nmap.org/dist/nmap-7.95-win32.zip',
                'https://nmap.org/dist/nmap-7.94-win32.zip'
            ],
            executable: 'nmap.exe'
        },
        masscan: {
            // Try to get a pre-built Windows binary, fallback to source
            url: 'https://github.com/robertdavidgraham/masscan/releases/download/1.3.2/masscan-1.3.2-win64-static.exe',
            fallbacks: [
                'https://github.com/robertdavidgraham/masscan/archive/refs/tags/1.3.2.zip'
            ],
            executable: 'masscan.exe'
        }
    },
    linux: {
        nmap: {
            // For Linux, we'll try to use system package or download portable
            command: 'which nmap',
            fallback_url: 'https://nmap.org/dist/nmap-7.95.tar.bz2',
            executable: 'nmap'
        },
        masscan: {
            command: 'which masscan', 
            fallback_url: 'https://github.com/robertdavidgraham/masscan/archive/refs/tags/1.3.2.tar.gz',
            executable: 'masscan'
        }
    }
};

function detectPlatform() {
    const platform = os.platform();
    if (platform === 'win32') return 'windows';
    if (platform === 'linux') return 'linux';  
    if (platform === 'darwin') return 'linux'; // Use Linux config for macOS
    throw new Error(`Unsupported platform: ${platform}`);
}

function ensureDirectory(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`📁 Created directory: ${dir}`);
    }
}

async function downloadFile(url, destination, timeout = 30000) {
    return new Promise((resolve, reject) => {
        console.log(`📥 Downloading: ${url}`);
        
        const file = fs.createWriteStream(destination);
        const request = https.get(url, (response) => {
            // Handle redirects
            if (response.statusCode === 302 || response.statusCode === 301 || response.statusCode === 307) {
                file.close();
                if (fs.existsSync(destination)) fs.unlinkSync(destination);
                return downloadFile(response.headers.location, destination, timeout)
                    .then(resolve).catch(reject);
            }
            
            if (response.statusCode !== 200) {
                file.close();
                if (fs.existsSync(destination)) fs.unlinkSync(destination);
                return reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
            }
            
            // Show progress
            const totalSize = parseInt(response.headers['content-length'], 10);
            let downloadedSize = 0;
            
            response.on('data', (chunk) => {
                downloadedSize += chunk.length;
                if (totalSize) {
                    const percent = ((downloadedSize / totalSize) * 100).toFixed(1);
                    process.stdout.write(`\r   Progress: ${percent}% (${Math.round(downloadedSize/1024)}KB/${Math.round(totalSize/1024)}KB)`);
                }
            });
            
            response.pipe(file);
            
            file.on('finish', () => {
                file.close();
                console.log(`\n✅ Downloaded: ${path.basename(destination)}`);
                resolve();
            });
            
        }).setTimeout(timeout);
        
        request.on('error', (err) => {
            file.close();
            if (fs.existsSync(destination)) fs.unlinkSync(destination);
            reject(err);
        });
        
        request.on('timeout', () => {
            request.destroy();
            file.close();
            if (fs.existsSync(destination)) fs.unlinkSync(destination);
            reject(new Error('Download timeout'));
        });
    });
}

function extractArchive(archivePath, extractTo, targetExecutable) {
    console.log(`📦 Extracting: ${path.basename(archivePath)}`);
    
    try {
        const ext = path.extname(archivePath).toLowerCase();
        
        if (ext === '.zip') {
            // Use PowerShell on Windows for reliable ZIP extraction
            if (os.platform() === 'win32') {
                const cmd = `powershell -command "Expand-Archive -Path '${archivePath}' -DestinationPath '${extractTo}' -Force"`;
                execSync(cmd, { stdio: 'inherit' });
            } else {
                execSync(`unzip -o "${archivePath}" -d "${extractTo}"`, { stdio: 'inherit' });
            }
        } else if (ext === '.bz2' || archivePath.includes('.tar.')) {
            execSync(`tar -xf "${archivePath}" -C "${extractTo}"`, { stdio: 'inherit' });
        }
        
        // Find the target executable
        const findExecutable = (dir, name) => {
            const files = fs.readdirSync(dir, { withFileTypes: true });
            for (const file of files) {
                const fullPath = path.join(dir, file.name);
                if (file.isDirectory()) {
                    const found = findExecutable(fullPath, name);
                    if (found) return found;
                } else if (file.name === name || file.name.includes(name)) {
                    return fullPath;
                }
            }
            return null;
        };
        
        const executablePath = findExecutable(extractTo, targetExecutable);
        if (executablePath && fs.existsSync(executablePath)) {
            console.log(`✅ Found executable: ${executablePath}`);
            return executablePath;
        }
        
        console.log(`⚠️  Could not find ${targetExecutable} in extracted files`);
        return null;
        
    } catch (error) {
        console.error(`❌ Extraction failed: ${error.message}`);
        return null;
    }
}

async function downloadBinary(config, targetPath, toolName) {
    const filename = path.basename(targetPath);
    
    // Skip if already exists
    if (fs.existsSync(targetPath)) {
        console.log(`✅ ${filename} already exists, skipping download`);
        return true;
    }
    
    // Try main URL first
    const urls = [config.url, ...(config.fallbacks || [])].filter(Boolean);
    
    for (const url of urls) {
        try {
            const downloadPath = path.join(TEMP_DIR, `${toolName}-${Date.now()}${path.extname(url)}`);
            
            await downloadFile(url, downloadPath);
            
            // If it's a direct executable, just copy it
            if (url.endsWith('.exe')) {
                fs.copyFileSync(downloadPath, targetPath);
                console.log(`✅ ${filename} installed successfully`);
                return true;
            }
            
            // If it's an archive, extract it
            const extractDir = path.join(TEMP_DIR, `extract-${toolName}-${Date.now()}`);
            ensureDirectory(extractDir);
            
            const executablePath = extractArchive(downloadPath, extractDir, config.executable);
            if (executablePath && fs.existsSync(executablePath)) {
                fs.copyFileSync(executablePath, targetPath);
                
                // Set executable permissions on Unix-like systems
                if (os.platform() !== 'win32') {
                    fs.chmodSync(targetPath, 0o755);
                }
                
                console.log(`✅ ${filename} installed successfully`);
                return true;
            }
            
        } catch (error) {
            console.log(`⚠️  Failed to download from ${url}: ${error.message}`);
            continue;
        }
    }
    
    console.log(`❌ Could not download ${toolName} from any source`);
    return false;
}

async function copySystemBinary(toolName, targetPath) {
    try {
        const platform = detectPlatform();
        const config = BINARY_URLS[platform][toolName];
        
        if (!config.command) return false;
        
        const systemPath = execSync(config.command, { encoding: 'utf8' }).trim();
        if (systemPath && fs.existsSync(systemPath)) {
            fs.copyFileSync(systemPath, targetPath);
            console.log(`✅ Copied system ${toolName} from: ${systemPath}`);
            return true;
        }
    } catch (error) {
        // System binary not found
    }
    return false;
}

async function main() {
    console.log('🚀 LEGION2 Automatic Binary Download');
    console.log('=====================================\n');
    
    try {
        const platform = detectPlatform();
        console.log(`🖥️  Platform: ${platform}`);
        
        ensureDirectory(TEMP_DIR);
        ensureDirectory(BINARIES_DIR);
        
        const tools = ['nmap', 'masscan'];
        const results = {};
        
        for (const tool of tools) {
            console.log(`\n🔧 Setting up ${tool}...`);
            
            const config = BINARY_URLS[platform][tool];
            if (!config) {
                console.log(`❌ No configuration for ${tool} on ${platform}`);
                results[tool] = false;
                continue;
            }
            
            const targetPath = path.join(BINARIES_DIR, config.executable);
            
            // Try downloading from URLs
            let success = await downloadBinary(config, targetPath, tool);
            
            // If download failed, try copying from system
            if (!success && platform !== 'windows') {
                console.log(`🔄 Trying to copy system ${tool}...`);
                success = await copySystemBinary(tool, targetPath);
            }
            
            results[tool] = success;
        }
        
        // Clean up temp directory
        if (fs.existsSync(TEMP_DIR)) {
            fs.rmSync(TEMP_DIR, { recursive: true, force: true });
        }
        
        // Summary
        console.log('\n📊 Installation Summary:');
        console.log('========================');
        
        let allSuccess = true;
        for (const [tool, success] of Object.entries(results)) {
            const config = BINARY_URLS[platform][tool];
            const targetPath = path.join(BINARIES_DIR, config.executable);
            
            if (success || fs.existsSync(targetPath)) {
                console.log(`✅ ${tool}: Ready (${targetPath})`);
            } else {
                console.log(`❌ ${tool}: Missing`);
                allSuccess = false;
            }
        }
        
        console.log('\n💡 LEGION2 Priority:');
        console.log('  1. Local binaries (what we just downloaded)');
        console.log('  2. System-installed tools (fallback)');
        
        if (allSuccess) {
            console.log('\n🎉 All tools ready! LEGION2 is fully configured.');
        } else {
            console.log('\n⚠️  Some tools missing, but LEGION2 will still work with available tools.');
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