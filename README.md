# csce465-hw2-danielbruni

The same VM was used from the previous homework. Installation information found as copied below:

# VM Install
A scratch install Ubuntu VM was downloaded as follows:
- 24.04 Desktop x86-64 ISO from official release
- Add new VM to VirtualBox
- 64 bit VM with ISO as virtual optic disk
- Completed Ubuntu install then eject disk
- Verification commands:
    - uname -m = x86_64
    - ip -brief address = [PRIVATE]
    - ip route = [PRIVATE]
- Virtualbox setting on VM for private NAT address
- 4 vCPUs and 8192 mb RAM (8GB)

# Python / Environment
This homework required the use of Python 3 and associated libraries (such as the cryptography library)
This was downloaded using the instructions from the homework file as follows:
  - Python environment — cryptography and testing. 
    - cd "$HOME/csce465-agentsec" 
    - python3 -m venv .venv 
    - source .venv/bin/activate 
    - python -m pip install --upgrade pip 
    - python -m pip install cryptography==49.0.0 pytest==9.1.1
    
  - Diffie–Hellman group file. Task 2 needs a standard ffdhe3072 parameter file. Generate it once, before starting Task 2: 
    - cd "$HOME/csce465-agentsec/hw2" 
    - openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem  
    - openssl dhparam -in ffdhe3072.pem -text -noout | head -3
   
# Testing / Automated Tests
During task 4, test cases needed to be curated within the tests/ directory at the file test_security.py. These test cases use pytest to run, and thus, executing the following command within the hw2 directory will compile and run the tests:
  - pytest -v
    - (NOTE: CANNOT RUN THE COMMAND IN THE hw2/tests/ DIRECTORY BECAUSE THEN THE NECESSARY FILES FROM THE hw2 DIRECTORY WILL NOT BE VISIBLE)
