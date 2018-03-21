<?php

namespace Ambta\DoctrineEncryptBundle\Encryptors;

use \ParagonIE\Halite\HiddenString;
use \ParagonIE\Halite\EncryptionKey;
use \ParagonIE\Halite\KeyFactory;
use \ParagonIE\Halite\Symmetric\Crypto;

/**
 * Class for encrypting and decrypting with the halite library
 *
 * @author Michael de Groot <specamps@gmail.com>
 */

class HaliteEncryptor implements EncryptorInterface
{
    private $encryptionKey;
    private $keyFile;

    /**
     * {@inheritdoc}
     */
    public function __construct(string $keyFile)
    {
        $this->encryptionKey = null;
        $this->keyFile = $keyFile;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        return \ParagonIE\Halite\Symmetric\Crypto::encrypt(new HiddenString($data), $this->getKey());
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        return \ParagonIE\Halite\Symmetric\Crypto::decrypt($data, $this->getKey())->getString();
    }

    private function getKey()
    {
        if ($this->encryptionKey === null) {
            try {
                $this->encryptionKey = \ParagonIE\Halite\KeyFactory::loadEncryptionKey($this->keyFile);
            } catch (\ParagonIE\Halite\Alerts\CannotPerformOperation $e) {
                $this->encryptionKey = KeyFactory::generateEncryptionKey();
                \ParagonIE\Halite\KeyFactory::save($this->encryptionKey, $this->keyFile);
            }
        }

        return $this->encryptionKey;
    }
}
