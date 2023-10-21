//Importing the Created Packages
import SSD_ECDSA_Crypto.ExtndBigInt_ECDSA;
import SSD_ECDSA_Crypto.OperECDSA_SSD1125;
import SSD_ECDSA_Crypto.KeyPair_SSD;
import SSD_ECDSA_Crypto.EllipticCurveSSD;
import SSD_ECDSA_Crypto.MessageVerify_ECDSA;
import SSD_ECDSA_Crypto.DigitalSign_ECDSA;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.*;  //For, getting the input using scanner
public class ECDSA_DigitalSign_SSD1125{
    public static void main(String[] args) throws Exception {
        System.out.println("*** Welcome To SSD's Digital Structure- ECDSA ***");
        //Creating public and private keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC","SunEC");
        ECGenParameterSpec ecsp = new ECGenParameterSpec("secp224r1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();
        System.out.println("(1) Private and Public have been Successfully generated, using ECDS Digital Signature Algo");
        System.out.println("Private Key: "+privKey.toString());
        System.out.println("Pulic Key: "+pubKey);
        
        System.out.println("\nElliptic Curve Digital Signature Algorithm: ");
        // Selecting the signature algorithm as ECDSA
        Signature s = Signature.getInstance("SHA256withECDSA","SunEC");
        //System.out.println(s);-> Here at this momont, it's not initialized
        s.initSign(privKey); 
        System.out.println("Signature: "+s);
        // Computing the signature.
        Scanner inpu=new Scanner(System.in);  
        System.out.println("\n\n <-<-<-<  Sender  <->->->");
        System.out.print("2. Enter the message✉: ");
        String messg=inpu.nextLine();
        byte[] msg = messg.getBytes("UTF-8");
        byte[] sig;
        //Computing and returning the updated signature
        s.update(msg);
        System.out.println("Updated Signature: "+s);
        System.out.println("\nFor Signature Verification, Enter your(Sender)private key: ");
        String pri=inpu.nextLine();        
        while (true)
        {
            if (pri.compareTo(privKey.toString())==0)
            {
                System.out.println("Yes 👍, Your Entered Private key is Verified,:-)");
                break;
            }
            else
            {
                System.out.println("🛅🔒🛅? !!!? Try Again !!! 🔒🛅🔒");
                System.out.println("Enter Again, Private Key: ");
                pri=inpu.nextLine(); }
        }
        sig = s.sign();
        System.out.println("\n(3)Successfully sent the Massage and Signature to reciever");
        System.out.println("\nSignature: "+sig);
        System.out.println("Modified Signature: "+s);
        System.out.println("Pulic Key: "+pubKey);
        //System.out.println(sg);
        
        // Verify the signature.
        System.out.println("\n\n <-<-<-<  Receiver End  <->->->");
        Signature sg = Signature.getInstance("SHA256withECDSA", "SunEC");
        System.out.println("(4)For confirmation+Security, Enter first 28 letters/values of (Sender's) Public key: ");
        String pb=inpu.nextLine();
        //"Sun EC public key, 224 bits"
        String pbk=pubKey.toString().substring(0,28);
        System.out.println(pbk);
        while (true)
        {
            if (pb.compareTo(pbk)+1==0)
            {
                System.out.println("Yes 👍, Your Entered Public key is Verified, :-)");
                break;
            }
            else
            {
                System.out.println
                ("🛅🔒?? !!!?  :-(   WRONG Public Key value, Kindly Try Again !!! ?🛅🔒");
                System.out.println("Enter Again, Public Key: ");
                pb=inpu.nextLine(); 
            }
            //System.out.println(pb.compareTo(pbk));
            //System.out.println("pb"+pb);
            //System.out.println("pbk"+pbk);
        }
        sg.initVerify(pubKey);
        System.out.println("Signature after verification: \n\t\t"+sg);
        sg.update(msg);
        //System.out.println("Signature after message verification: "+sg);
        //boolean validitingSignature = sg.verify(sig);
        System.out.println(sg);
        System.out.println("Computed Signature: "+sig);
        String sent_msg=new String(msg);
        System.out.println("\nChecking if the provided message is same as our computed Signature: ");
        boolean validitingSignature = sg.verify(sig);
        System.out.println(validitingSignature);
        System.out.println("Sent Message: "+sent_msg);
        if (Boolean.compare(validitingSignature,true)==0)
            System.out.println("The Message is Successfully receieved, Using ECDSA Algorithm, \n Thank You  :-)");
        else
            System.out.println("  :-(   The message is not successfully received");
    }
}
