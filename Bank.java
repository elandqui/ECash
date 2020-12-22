// Eric Landquist
// Virginia Tech
// October 11, 1998

// Bank.java

import java.util.Random;
import java.math.BigInteger;
import java.io.*;

// This class will implement a model of a Bank for an implementation of an e-cash system.

class Bank {

//The size of the tables storing user information
public static final int SIZE = 100;

// The number of bits in any key.
public static final int BITS = 1024;

// The users, and their information
public static User user;
public static BigInteger credit;
public static BigInteger idNum;
public static BigInteger pubKey;
public static BigInteger[][] transaction = new BigInteger[3][10000];
public static BigInteger tempRandom;
public static int numTrans;

// The Bank's RSA encryption key.
public static final BigInteger e = new BigInteger("31753334330785150921894247556736621874338756161197386784443128943016484609052387737301386274328387908878116471785658283254806375662817759052135684884271540381648730869694047818657115366581875466246609007215234708592315281388625426999307227281598582625973965498145364082908130504388456234882584510098319974757");

// The Bank's RSA decryption key.
private static final BigInteger d = new BigInteger("7220177207478463372373270572647473490271041342307593106077216877292988799357967410288391454228663751575348208009012349367395277168909604654897276974533227416490956192787839982673193347611894907623123164824525590711762650888105656759709492303532870423144447150060464773872480720480881517344275361641900422873");

// The RSA modulus: 1024 bits.
public static final BigInteger modulus = new BigInteger("67121633100854333760823216471326079676039838960980375144787957703044941147081296059123997261399910613390603844272962446505560297966424631213047304914323469022909185522090033023879429769168557156271032061067995076629568463341021245792743115819466961853594162377852172085064974026021473181363138895145026648893");

// A prime used as a public key: 1024 bits and less than the RSA modulus.
public static final BigInteger p = new BigInteger("39176653485168937261236812439702609831448508122550980022664302727035222613253299329797670339773568468434872765577223730056267370338041289138500934868132480441658158377096480993729925515459639920746270053862138214932560550088228595580056165885844547511846459310603503565414543691466452907450326724132154736333");

// A prime that divides p-1
public static final BigInteger q = new BigInteger("1088240374588026035034355901102850273095791892293082778407341742417645072590369425827713064993710235234302021266033992501562982509390035809402803746337013345601615510474902249825831264318323331131840834829503839303682237502450794321668226830162348541995734980850097321261515102540734802984731297892559853787");

// A generator such that g^q = 1 (mod p)
public static final BigInteger g = new BigInteger("10");

// A storage of values that are used for verification.
public static BigInteger n;
public static BigInteger c;

// A file to store all active transaction numbers.
private static final String BANKFILE = "nums.bnk";

// An array to hold active transaction numbers, and the number of such transactions.
private static BigInteger[] activeNums = new BigInteger[50];
private static int active = 0;

// Method: Bank()
// Constructor
// Purpose:	To perform bank operations with a given user.

	public Bank(User user){
		this.user = user;
		
		RandomAccessFile userFile;
		
		try {
			// Open up the user's file.
			userFile = new RandomAccessFile(user.getName()+".bnk", "rw");
			
			// Checking to see if the user exists. If his file has nothing in it, he has no account.
			if (userFile.length() == 0) {
				error("User "+user.getName()+" does not exist");
				return;
			}
			
		} catch (IOException ioe) {
			error("Could not open file.");
			return;
		}
		
		// Now we fill in the information about the user.
		byte[] buffer = new byte[BITS/8];
		int bytesRead = 1024;
		try {
			// Get the account number
			userFile.read(buffer);
			idNum = new BigInteger(buffer);
			
			// Get the user's public key.
			userFile.read(buffer);
			pubKey = new BigInteger(buffer);
			
			// Find out how much money is in the account.
			userFile.read(buffer);
			byte[] creditBytes = new byte[buffer[0]];
			System.arraycopy(buffer, BITS/8 - buffer[0], creditBytes, 0, buffer[0]);
			credit = new BigInteger(creditBytes);
			
			// Get all the transaction numbers read in.
			bytesRead = userFile.read(buffer);
			int i=0;
			while (bytesRead > 0) {
				// Getting all the x and y coordinate data.
				transaction[0][i] = new BigInteger(buffer);
				bytesRead = userFile.read(buffer);
				transaction[1][i] = new BigInteger(buffer);
				bytesRead = userFile.read(buffer);
				transaction[2][i] = new BigInteger(buffer);
				bytesRead = userFile.read(buffer);
				i++;
			}
			numTrans = i;
			userFile.close();
			
			// Open the bankfile.
			RandomAccessFile bankFile = new RandomAccessFile(BANKFILE, "r");

			// Read in all the active transaction numbers.
			bytesRead = bankFile.read(buffer);
			while (bytesRead > 0) {
				activeNums[active] = new BigInteger(buffer);
				// Don't want transaction numbers that are zero.
				if (activeNums[active].equals(new BigInteger("0")))
					break;
				active++;
				bytesRead = bankFile.read(buffer);
			}
			bankFile.close();
				
		} catch (IOException ioe) {
			error("Could not read in all the data.");
		}
		
		// All the information about the user is now stored in memory.
		
	} // end Bank()
	
// Method:	withdraw()
// Purpose:	To withdraw a given amount of money from a certain account.

	public static BigInteger[] withdraw(BigInteger[] request) {
		BigInteger zero = new BigInteger("0");
		BigInteger[] zerozero = {zero, zero};

		// Check the validity of the random transaction number.
		BigInteger trans = decrypt(request[0]);
		boolean valid=false;
		if(trans.equals(tempRandom)){
			// Getting the user's account number.
			BigInteger accnt = decrypt(request[1].multiply(trans.modInverse(modulus)));
			if(accnt.equals(idNum)) {
				valid = true;
			}
		}
		
		if (!valid) {
			error("Withdrawal request not verified. Transaction cancelled.");
			return zerozero;
		}
		// Find out how much the user wants to withdraw.
		BigInteger amount = decrypt(request[2].multiply(trans.modInverse(modulus))).modPow(pubKey, modulus).mod(modulus);
		// If Alice tries to take out more than she has, then there is no transaction.
		if (amount.compareTo(credit) == 1) {
			error("Can't withdraw more money than is in account.");
			return zerozero;
		}
				
		// Update Alice's account.
		credit = credit.subtract(amount);
		
		System.out.println("Now have $"+credit.toString()+" in your account.");

		// Updating the Bank's account for the User.
		byte[] money = new byte[BITS/8];
		money[0] = (byte)credit.toByteArray().length;
		System.arraycopy(credit.toByteArray(), 0, money, BITS/8 - money[0], money[0]);
		
		// Write to file.
		try {
			RandomAccessFile bankFile = new RandomAccessFile(user.getName()+".bnk", "rw");
			bankFile.seek(BITS/4);
			bankFile.write(money);
			bankFile.close();
		} catch (IOException ioe) {
			error("Cannot update bank file.");
			return zerozero;
		}
		
		// Update the Bank's records.
		activeNums[active] = trans;
		active++;
		// Write this information to file.
		byte[] transBytes = trans.toByteArray();
		try {
			RandomAccessFile bankFile = new RandomAccessFile(BANKFILE, "rw");
			bankFile.seek((active-1)*(BITS/8));
			if (transBytes.length < 128) {
				byte[] tempBytes = new byte[BITS/8];
				System.arraycopy(transBytes, 0, tempBytes, BITS/8 - transBytes.length, transBytes.length);
				bankFile.write(tempBytes);
			}
			else 
				bankFile.write(transBytes);
			bankFile.close();
		} catch (IOException ioe) {
			error("Could not update Bank File.");
		}

		// Send Alice the coin.
		BigInteger[] returnCoin = {trans.modPow(pubKey, modulus), (trans.multiply(decrypt(amount.modPow(pubKey, modulus))).mod(modulus)), decrypt(request[3])};
		update();
		return returnCoin;
	} // end withdraw()
	
// Method: 	deposit()
// Purpose:	To deposit money into a certain account, and to double check that the user is not, re-depositing a coin.
// Parameters: coin - the digital coin to be deposited in the bank
//			   user - the user that is depositing money.

	public static boolean deposit(BigInteger[] coin) {
		BigInteger dollars;
		
		// Check the validity of the random transaction number.
		BigInteger trans1 = decrypt(coin[0]);
		
		boolean valid = false;
		if (tempRandom.equals(trans1)) {
			// Getting the user's account number.
			BigInteger accnt = decrypt(coin[2].multiply(trans1.modInverse(modulus)));
			if(accnt.equals(idNum))
				valid = true;
		}
		
		if (!valid) {
			error("Deposit request not verified. Transaction cancelled.");
			return false;
		}
		
		// Get the real transaction number
		BigInteger trans = decrypt(coin[1].multiply(trans1.modInverse(modulus)).mod(modulus));
		
		// If the transaction number is duplicated, we have a possible double-depositor.
		boolean unique = true;
		int count = 0;
		for(int i=0; i<active; i++) {
			if(activeNums[i].equals(trans)) {
				count++;
				break;
			}
		}
	
		// If the transaction number is no longer there, then it has been deleted from a past use, so
		// we do not have a unique transaction number, hence a double depositing.
		if(count == 0) {
			unique = false;
		}

		// Extract the two challenge values.
		c = coin[3].multiply(trans1.modInverse(p)).mod(p);
		n = coin[4].multiply(trans1.modInverse(p)).mod(p);

		// Then make the challenge.
		BigInteger[] coords2 = challenge(user);

		// If the coin is not valid, the transaction does not process
		BigInteger zero = new BigInteger("0");
		if (coords2[0].equals(zero) && coords2[1].equals(zero)){
			error("Authorization invalid. Deposit cancelled.");
			return false;
		}
		
		// Again, if Bob double-deposited, then we can double check with his personal information.
		BigInteger[] coords = new BigInteger[2];
		
		if (!unique) {
			for(int j=0; j<numTrans; j++) {
				if (trans.equals(transaction[0][j])) {
					coords[0] = transaction[1][j];
					coords[1] = transaction[2][j];
					break;
				}
			}
			// The slope of the line formed which will be the user's ID number.
			BigInteger slope = (coords[1].subtract(coords2[1])).multiply((coords[0].subtract(coords2[0])).modInverse(q)).mod(q);
		
			error("Coin double spent. Illegal transaction.");
			if(slope.equals(idNum)){
				error("User "+user.getName()+" attempted to deposit coin twice. Transaction cancelled.");
			}
			return false;
		}

		// If it cleared, then we can add in the coordinates.
		// Given the size of the random transaction numbers, the odds that we will get
		// 	two different valid transactions with the same number is extremely small,
		// 	about the odds that God didn't create the Universe, so we will say that such
		// a case is impossible. Thus in the block immediately above, if the first if statement went through,
		// we assume the second will as well.
		
		transaction[0][numTrans] = trans;
		transaction[1][numTrans] = coords2[0];
		transaction[2][numTrans] = coords2[1];
		numTrans++;
		
		// The amount that the user is depositing.
		dollars = encrypt(coin[5].multiply(trans1.modInverse(modulus)).modPow(pubKey, modulus));
			
		// Add dollars dollars to the account.
		credit = credit.add(dollars);
		System.out.println("User "+user.getName()+ " deposited $" + dollars.toString() + ". Updated account is $"+credit.toString());
		
		// Now take out the now inactive transaction number.
		for(int j=0; j<active; j++) {
			if (trans.equals(activeNums[j])) {
				for(int k=j; k<active-1; k++) 
					activeNums[j] = activeNums[j+1];
				activeNums[active-1] = new BigInteger("0");
				active--;
			}
		}
		
		// Now we write the transaction numbers to the file
		try {
			RandomAccessFile bankFile = new RandomAccessFile(BANKFILE, "rw");
			byte[] realBytes = new byte[BITS/8];
			if (active != 0){
				byte[] tempBytes = activeNums[0].toByteArray();
				for (int l=0; l<active; l++) {
					if(tempBytes.length != 128 ){
						System.arraycopy(tempBytes, 0, realBytes, BITS/8 - tempBytes.length, tempBytes.length);
						bankFile.write(realBytes);
					}
					else 
						bankFile.write(tempBytes);
					realBytes = new byte[BITS/8];
				}
			}
			// Filling in hte last set of bits.
			bankFile.write(realBytes);
		} catch(IOException ioe) {
			error("Cannot update the Bank file.");
		}
		
		return true;

	} // end deposit()
	
// Method:	keyExchange()
// Purpose: To generate a random key in common with one other user using the Diffie-Hellman key exchange.
// Parameter: rand - if the user's secret random number is A, then rand = g^A (mod p).

	public static BigInteger keyExchange(BigInteger rand) {
		// If B is the Bank's random number, returns: g^B (mod p).

		// The Bank's random number
		BigInteger bankRandom = new BigInteger(BITS, new Random()).mod(q);

		// Put in the new random number.
		tempRandom = rand.modPow(bankRandom, p);

		return g.modPow(bankRandom, p);
	} // end keyExchange
	
// Method:	challenge()
// Purpose: To challenge the validity of a deposit

	public static BigInteger[] challenge(User bob) {
		// The x and y coordinates that the user returns when challenges
		BigInteger[] x_y = bob.respond(new BigInteger(BITS, new Random()).mod(q));
		
		// Testing the validity of the data.
		if( respond(x_y[0], x_y[1]))
			return x_y;
		else {
			BigInteger zero = new BigInteger("0");
			BigInteger[] zerozero = {zero, zero};
			return zerozero;
		}
	}
	
// Method:	respond()
// Purpose:	To test the data to see if it's valid.

	public static boolean respond(BigInteger x, BigInteger y) {
		// Check the shadow of the linear equation.
		if(g.modPow(y, p).equals(n.modPow(x, p).multiply(c).mod(p)))
			return true;
		
		else 
			return false;
	}
	
// Method: 	encrypt()
// Purpose:	To encrypt an integer using the RSA protocol.

	public static BigInteger encrypt(BigInteger m) {
		return m.modPow(e, modulus);
	}

// Method:	decrypt()
// Purpose:	To decrypt an integer, using the RSA protocol.

	public static BigInteger decrypt(BigInteger c) {
		return c.modPow(d, modulus);
	}

// Method:	update()
// Purpose:	To save all information on file.

	public static void update() {
		// Now the update for the user file is done. Now do the transaction numbers.
		try {
			
			RandomAccessFile transFile = new RandomAccessFile(user.getName()+".bnk", "rw");
			byte[] tempBytes;
			// Go to the credit record.
			transFile.seek(BITS/4);
			byte[] buffer = new byte[BITS/8];
			buffer[0] = (byte)credit.toByteArray().length;
			System.arraycopy(credit.toByteArray(), 0, buffer, BITS/8 - buffer[0], buffer[0]);
			transFile.write(buffer);
			
			buffer = new byte[BITS/8];
			for(int i=0; i<numTrans; i++) {
				buffer = new byte[BITS/8];
				tempBytes = transaction[0][i].toByteArray();
				if (tempBytes.length != BITS/8) {
					System.arraycopy(tempBytes, 0, buffer, BITS/8 - tempBytes.length, tempBytes.length);
					transFile.write(buffer);
				}
				else 
					transFile.write(tempBytes);
					
				buffer = new byte[BITS/8];
				tempBytes = transaction[1][i].toByteArray();
				if (tempBytes.length != BITS/8) {
					System.arraycopy(tempBytes, 0, buffer, BITS/8 - tempBytes.length, tempBytes.length);
					transFile.write(buffer);
				}
				else 
					transFile.write(tempBytes);
					
				buffer = new byte[BITS/8];
				tempBytes = transaction[2][i].toByteArray();
				if (tempBytes.length != BITS/8) {
					System.arraycopy(tempBytes, 0, buffer, BITS/8 - tempBytes.length, tempBytes.length);
					transFile.write(buffer);
				}
				else 
					transFile.write(tempBytes);
				
			}
			
			transFile.close();
		} catch (IOException ioe) {
			error("Could not open file.");
			return;
		}
		
	} // end update()
	
// Method: check()
// Purpose: To find out which user double spent given an account number.

	public static boolean check(BigInteger a) {
		a = decrypt(a);
		// Open the current directory
		File directory = new File(".");
		
		// Get the list of files in this directory.
		String[] files = directory.list();
		byte[] buffer = new byte[BITS/8];
		RandomAccessFile userFile;
		
		// Look at every file name.
		for(int i=0; i< files.length; i++) {
			char[] chars = files[i].toCharArray();
			// All valid .bnk files will have at least 4 characters.
			if (chars.length > 4 ) {
				// Check the file extensions themselves.
				if (chars[chars.length - 4] == '.' &&
					chars[chars.length - 3] == 'b' &&
					chars[chars.length - 2] == 'n' &&
					chars[chars.length - 1] == 'k' ) {
					try {
						userFile = new RandomAccessFile(files[i], "r");
						userFile.read(buffer);
						// Compare the two account numbers.
						if (a.equals(new BigInteger(buffer))){
							String thief = new String(chars, 0, chars.length-4);
							error("The user: "+ thief+ " has double spent a coin!");
							userFile.close();
							return true;
						}
						userFile.close();
					} catch (IOException ioe) {
						error("Could not open user file.");
						return false;
					}
				} // end if 
			} // end if
		} // end for loop
		
		// If the loop quits, then there is no user.
		return false;
	}
						

// Method:	error()

	public static void error(String message){
		System.out.println("Error: " + message);
	} // end error()

} // end class Bank