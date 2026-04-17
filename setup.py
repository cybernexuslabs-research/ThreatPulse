#!/usr/bin/env python3
"""
Setup script for CVE Tracking System
Initializes database and runs first collection
"""

import os
import sys
import sqlite3
import subprocess

def check_dependencies():
    """Check if required packages are installed"""
    print("Checking dependencies...")
    try:
        import requests
        print("✓ requests module found")
        return True
    except ImportError:
        print("✗ requests module not found")
        print("\nPlease install dependencies:")
        print("  pip install -r requirements.txt")
        return False

def initialize_database():
    """Initialize the database with schema"""
    print("\nInitializing database...")
    
    if os.path.exists('cves.db'):
        response = input("Database already exists. Recreate? (y/N): ")
        if response.lower() != 'y':
            print("Keeping existing database")
            return True
        os.remove('cves.db')
        print("Removed existing database")
    
    try:
        conn = sqlite3.connect('cves.db')
        with open('schema.sql', 'r') as f:
            schema = f.read()
            conn.executescript(schema)
        conn.commit()
        conn.close()
        print("✓ Database initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        return False

def run_first_collection():
    """Run the collector for the first time"""
    print("\nRunning first CVE collection...")
    response = input("This will download ~100MB of data. Continue? (Y/n): ")
    if response.lower() == 'n':
        print("Skipping initial collection")
        return True
    
    try:
        subprocess.run(['python3', 'cve_collector.py'], check=True)
        print("\n✓ Initial collection completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Collection failed: {e}")
        return False
    except FileNotFoundError:
        print("\n✗ Could not find cve_collector.py")
        return False

def show_next_steps():
    """Display next steps for the user"""
    print("\n" + "="*70)
    print("SETUP COMPLETE!")
    print("="*70)
    print("\nNext steps:")
    print("\n1. Create your asset configuration file:")
    print("   python3 cve_collector.py --init-assets")
    print("\n2. Run the collector again to update relevance scores:")
    print("   ./cve_collector.py")
    print("\n3. View reports:")
    print("   ./cve_reporter.py --dashboard")
    print("   ./cve_reporter.py --relevant")
    print("   ./cve_reporter.py --exploits-only")
    print("\n4. Set up automated collection (optional):")
    print("   crontab -e")
    print("   Add line: */30 * * * * /path/to/cve_collector.py >> /var/log/cve.log 2>&1")
    print("\n5. Read the full documentation:")
    print("   cat README.md")
    print("\n" + "="*70)

def main():
    print("="*70)
    print("CVE Tracking System - Setup")
    print("="*70)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize database
    if not initialize_database():
        sys.exit(1)
    
    # Run first collection
    #if not run_first_collection():
    #    print("\nSetup incomplete, but you can run the collector manually later.")
    
    # Show next steps
    show_next_steps()

if __name__ == "__main__":
    main()
