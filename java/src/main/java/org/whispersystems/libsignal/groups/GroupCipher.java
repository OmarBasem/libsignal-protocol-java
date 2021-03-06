/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 * <p>
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;


import com.sun.org.apache.xpath.internal.operations.Bool;
import org.whispersystems.libsignal.DecryptionCallback;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.groups.ratchet.SenderChainKey;
import org.whispersystems.libsignal.groups.ratchet.SenderMessageKey;
import org.whispersystems.libsignal.groups.state.SenderKeyRecord;
import org.whispersystems.libsignal.groups.state.SenderKeyState;
import org.whispersystems.libsignal.groups.state.SenderKeyStore;
import org.whispersystems.libsignal.protocol.SenderKeyMessage;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;

import org.whispersystems.libsignal.logging.Log;


/**
 * The main entry point for Signal Protocol group encrypt/
 * <p>
 * <p>
 * <p>
 * operations.
 * <p>
 * Once a session has been established with {@link org.whispersystems.libsignal.groups.GroupSessionBuilder}
 * and a {@link org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage} has been
 * distributed to each member of the group, this class can be used for all subsequent encrypt/decrypt
 * operations within that session (ie: until group membership changes).
 *
 * @author Moxie Marlinspike
 */
public class GroupCipher {

    static final Object LOCK = new Object();

    private final SenderKeyStore senderKeyStore;
    private final SenderKeyName senderKeyId;

    public GroupCipher(SenderKeyStore senderKeyStore, SenderKeyName senderKeyId) {
        this.senderKeyStore = senderKeyStore;
        this.senderKeyId = senderKeyId;
    }

    /**
     * Encrypt a message.
     *
     * @param paddedPlaintext The plaintext message bytes, optionally padded.
     * @return Ciphertext.
     * @throws NoSessionException
     */


    /**
     * Decrypt a SenderKey group message.
     *
     * @param senderKeyMessageBytes The received ciphertext.
     * @return Plaintext
     * @throws LegacyMessageException
     * @throws InvalidMessageException
     * @throws DuplicateMessageException
     */


    private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
            throws InvalidMessageException {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);
            return cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
                InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidMessageException(e);
        }
    }

    private byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);
            return cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                IllegalBlockSizeException | BadPaddingException | java.security.InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    private static class NullDecryptionCallback implements DecryptionCallback {
        @Override
        public void handlePlaintext(byte[] plaintext) {
        }
    }

    public void ratchetChain(int steps) throws NoSessionException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);
                SenderKeyState senderKeyState = record.getSenderKeyState();
                for (int i = 0; i < steps; i++) {
                    senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());
                }
                senderKeyStore.storeSenderKey(senderKeyId, record);
            } catch (InvalidKeyIdException e) {
                throw new NoSessionException(e);
            }
        }
    }

    public byte[] encrypt(byte[] paddedPlaintext, Boolean isChat, int steps) throws NoSessionException, DuplicateMessageException, InvalidMessageException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);
                SenderKeyState senderKeyState = record.getSenderKeyState();

                SenderChainKey firstSenderChainKey = senderKeyState.getSenderChainKey();
                SenderChainKey senderChainKey = senderKeyState.getSenderChainKey();
                System.out.println("ITERATIONSSS " + senderChainKey.getIteration());
                while (senderChainKey.getIteration() < steps) {
                    System.out.println("NEW KEY");
                    senderChainKey = senderChainKey.getNext();
                    senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
                }
                senderKeyState.setSenderChainKey(senderChainKey);

//                senderKeyStore.storeSenderKey(senderKeyId, record);
                SenderMessageKey senderKey = senderKeyState.getSenderChainKey().getSenderMessageKey();
//                SenderMessageKey senderKey = getSenderKey(senderKeyState, steps, false);
//                senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());

//                if (isChat)
//                else
//                    senderKey = senderKeyState.getSenderChainKey().getNext().getSenderMessageKey();

                byte[] ciphertext = getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext);

                System.out.println("WHATITERATION? " + senderKey.getIteration());
                SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyState.getKeyId(),
                        senderKey.getIteration(),
                        ciphertext,
                        senderKeyState.getSigningKeyPrivate());

                senderKeyState.setSenderChainKey(firstSenderChainKey);


//                if (isChat)
//                senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());

                senderKeyStore.storeSenderKey(senderKeyId, record);

                return senderKeyMessage.serialize();
            } catch (InvalidKeyIdException e) {
                throw new NoSessionException(e);
            }
        }
    }

    public byte[] decrypt(byte[] senderKeyMessageBytes, Boolean isChat)
            throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {
        return decrypt(senderKeyMessageBytes, new NullDecryptionCallback(), isChat);
    }


    public byte[] decrypt(byte[] senderKeyMessageBytes, DecryptionCallback callback, Boolean isChat)
            throws LegacyMessageException, InvalidMessageException, DuplicateMessageException,
            NoSessionException {
        synchronized (LOCK) {
            try {
                SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);

                if (record.isEmpty()) {
                    throw new NoSessionException("No sender key for: " + senderKeyId);
                }

                SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyMessageBytes);
                SenderKeyState senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId());

                senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());

                SenderMessageKey senderKey = getSenderKey(senderKeyState, senderKeyMessage.getIteration(), isChat);

                byte[] plaintext = getPlainText(senderKey.getIv(), senderKey.getCipherKey(), senderKeyMessage.getCipherText());

                callback.handlePlaintext(plaintext);

                senderKeyStore.storeSenderKey(senderKeyId, record);

                return plaintext;
            } catch (org.whispersystems.libsignal.InvalidKeyException | InvalidKeyIdException e) {
                throw new InvalidMessageException(e);
            }
        }
    }

    private SenderMessageKey getSenderKey(SenderKeyState senderKeyState, int iteration, Boolean isChat)
            throws DuplicateMessageException, InvalidMessageException {
        SenderChainKey senderChainKey = senderKeyState.getSenderChainKey();


        if (senderChainKey.getIteration() > iteration) {
            if (senderKeyState.hasSenderMessageKey(iteration)) {
                return senderKeyState.removeSenderMessageKey(iteration, isChat);
            } else {
                throw new DuplicateMessageException("Received message with old counter: " +
                        senderChainKey.getIteration() + " , " + iteration);
            }
        }

        if (iteration - senderChainKey.getIteration() > 2000) {
            throw new InvalidMessageException("Over 2000 messages into the future!");
        }
        while (senderChainKey.getIteration() < iteration) {
            if (isChat)
                senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
            senderChainKey = senderChainKey.getNext();
        }

        if (isChat)
            senderKeyState.setSenderChainKey(senderChainKey.getNext());

        return senderChainKey.getSenderMessageKey();
    }
}
