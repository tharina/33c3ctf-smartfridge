#!/usr/bin/env ruby

require 'socket'
require 'openssl'
require 'securerandom'

SERVER_IP = 'localhost'
SERVER_PORT = 12345

def e k, plaintext
    cipher = OpenSSL::Cipher.new 'AES-128-ECB'
    cipher.encrypt
    cipher.key = k
    cipher.padding = 0

    cipher.update(plaintext) + cipher.final
end

def encrypt k, plaintext
    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.encrypt
    cipher.key = k
    cipher.iv = "\x00" * 16
    
    cipher.update(plaintext) + cipher.final
end

def encrypt_without_padding k, plaintext
    cipher = OpenSSL::Cipher.new 'AES-128-CBC'
    cipher.encrypt
    cipher.key = k
    cipher.iv = "\x00" * 16
    cipher.padding = 0
    
    cipher.update(plaintext) + cipher.final
end

def decrypt k, ciphertext
    decipher = OpenSSL::Cipher.new 'AES-128-CBC'
    decipher.decrypt
    decipher.key = k
    decipher.iv = "\x00" * 16
    
    decipher.update(ciphertext) + decipher.final
end

def c1 tk, rand
    e(tk, rand)
end

def s1 tk, rand1, rand2
    r = rand1[8..15] + rand2[8..15]
    e tk, r
end

class TCPSocket
    def recvn(n, flags=0)
        res = ""
        while res.size < n
            res << self.recv(n - res.size, flags)
        end
        res
    end
end


def open i
    puts "Opening shelf #{i}"
    data = "OPEN #{i}"
    enc = encrypt $stk, data
    p = [enc.size + 4].pack("I") + enc
    $s.send p, 0
    puts "-------------------------------------"
end

def close
    puts "Closing shelf"
    data = "CLOSE"
    enc = encrypt $stk, data
    p = [enc.size + 4].pack("I") + enc
    $s.send p, 0
    puts "-------------------------------------"
end


def list
    puts "Content:"
    data = "LIST"
    enc = encrypt $stk, data
    p = [enc.size + 4].pack("I") + enc
    $s.send p, 0

    size = $s.recvn(4).unpack("I").first
    p size
    answer = $s.recvn(size - 4)
    dec = decrypt($stk, answer)
    puts dec
    puts "-------------------------------------"
end

def show i
    puts "Showing item in slot #{i}"
    data = "SHOW #{i}"
    enc = encrypt $stk, data
    p = [enc.size + 4].pack("I") + enc
    $s.send p, 0

    size = $s.recvn(4).unpack("I").first
    answer = $s.recvn(size - 4)
    dec = decrypt($stk, answer)
    puts dec
    puts "-------------------------------------"
end

def put i, name, description
    puts "Putting #{name} into slot #{i}"
    data = "PUT #{i} #{name} #{description}"
    enc = encrypt $stk, data
    p = [enc.size + 4].pack("I") + enc
    $s.send p, 0
    puts "-------------------------------------"
end

def take i
    puts "Taking item from slot #{i}"
    data = "TAKE #{i}"
    enc = encrypt $stk, data
    p = [enc.size + 4].pack("I") + enc
    $s.send p, 0

    size = $s.recvn(4).unpack("I").first
    answer = $s.recvn(size - 4)
    dec = decrypt($stk, answer)
    puts dec
    puts "-------------------------------------"
end



$s = TCPSocket.new SERVER_IP, SERVER_PORT

puts "Connected"


# extracted from pcap
mConfirm = ["e66d09aaad15d191b6fa3a474e98a46c"].pack("H*")
sConfirm = ["ccca69ed88dcdbb88c3b18c0baecd436"].pack("H*")
mRand =    ["3119f45f7499cda007670b2f51fd4127"].pack("H*")
sRand =    ["d01d9f62f9e00c55b9dda4083c12b7fb"].pack("H*")

puts "Offline bruteforcing passcode for shelf 2"
digits = ['0','1','2','3','4','5', '6','7','8','9']
passcode = ""
for p in digits.repeated_permutation(6) do
    passcode = p.join("")
    tk = [passcode.to_i(10), 0].pack("QQ")
    if c1(tk, mRand) == mConfirm
        puts "Found passcode: #{passcode}"
        break
    end
end



mRand = SecureRandom.random_bytes 16
p "mRand:    " + mRand.unpack("H*").first
mConfirm = c1(tk, mRand)
p "mConfirm: " + mConfirm.unpack("H*").first

# set userID 2
p = ([21].pack("I") + "\x2" + mConfirm)
$s.send p, 0
sConfirm = $s.recvn 20
sConfirm = sConfirm[4...20]
p "sConfirm: " + sConfirm.unpack("H*").first

p = ([20].pack("I") + mRand)
$s.send p, 0
sRand = $s.recvn 20
sRand = sRand[4...20]
p "sRand:    " + sRand.unpack("H*").first

sConfirmCheck = c1(tk, sRand)
p "Check:    " + sConfirmCheck.unpack("H*").first
if(sConfirmCheck == sConfirm)
    $stk = s1(tk, sRand, mRand)
    p "STK:      " +  $stk.unpack("H*").first
    puts "Paired"
else
    puts "Pairing failed"
    exit
end


puts "-------------------------------------"

open 2
list
show 0
