#!/usr/bin/env python3
"""
Setup script for the Multi-Ecosystem Dependency Scanner
"""
import subprocess
import sys
import os

def install_dependencies():
    """Install required dependencies"""
    print("🚀 Setting up Multi-Ecosystem Dependency Scanner...")
    print("=" * 50)
    
    # Check if requirements.txt exists
    if os.path.exists('requirements.txt'):
        print("📦 Installing dependencies from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
            print("✅ All dependencies installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            sys.exit(1)
    else:
        # Fallback to individual installation
        dependencies = [
            "requests>=2.25.0",
            "pipdeptree>=2.0.0",
            "flask>=2.0.0"
        ]
        
        print("📦 Installing dependencies individually...")
        for dep in dependencies:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                print(f"✅ Installed {dep}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install {dep}: {e}")
                sys.exit(1)
    
    print("\n🎉 Setup complete!")
    print("\nUsage:")
    print("  python scan.py examples/requirements.txt    # Scan Python dependencies")
    print("  python scan.py examples/package.json        # Scan JavaScript dependencies")
    print("  python web.py                               # Launch web interface")
    print("  python test.py                              # Run test suite")
    print("\nFor more information, see README.md")

if __name__ == "__main__":
    install_dependencies()
