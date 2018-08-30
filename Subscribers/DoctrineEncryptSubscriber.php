<?php

namespace Ambta\DoctrineEncryptBundle\Subscribers;

use ReflectionClass;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Events;
use Doctrine\ORM\UnitOfWork;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Util\ClassUtils;
use Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use ReflectionProperty;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Appended to end of encrypted value
     */
    const ENCRYPTION_MARKER = '<ENC>';

    /**
     * Encryptor interface namespace
     */
    const ENCRYPTOR_INTERFACE_NS = 'Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface';

    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'Ambta\DoctrineEncryptBundle\Configuration\Encrypted';

    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private $encryptor;

    /**
     * Annotation reader
     * @var \Doctrine\Common\Annotations\Reader
     */
    private $annReader;

    /**
     * Used for restoring the encryptor after changing it
     * @var string
     */
    private $restoreEncryptor;

    /**
     * Cached encrypted values
     * @var array
     */
    private $propertyCache = [];

    /**
     * Count amount of decrypted values in this service
     * @var integer
     */
    public $decryptCounter = 0;

    /**
     * Count amount of encrypted values in this service
     * @var integer
     */
    public $encryptCounter = 0;

    /**
     * Initialization of subscriber
     *
     * @param Reader $annReader
     * @param string $encryptorClass  The encryptor class.  This can be empty if a service is being provided.
     * @param EncryptorInterface|NULL $service (Optional)  An EncryptorInterface.
     *
     * This allows for the use of dependency injection for the encrypters.
     */
    public function __construct(Reader $annReader, EncryptorInterface $encryptor)
    {
        $this->annReader = $annReader;
        $this->encryptor = $encryptor;
        $this->restoreEncryptor = $this->encryptor;
    }

    /**
     * Change the encryptor
     * @param [type] $[name] [<description>]
     * @param EncryptorInterface $encryptorClass
     */
    public function setEncryptor(EncryptorInterface $encryptorClass = null)
    {
        $this->encryptor = $encryptorClass;
    }

    /**
     * Get the current encryptor
     *
     * @return EncryptorInterface returns the encryptor class or null
     */
    public function getEncryptor()
    {
        return $this->encryptor;
    }

    /**
     * Restore encryptor set in config
     */
    public function restoreEncryptor()
    {
        $this->encryptor = $this->restoreEncryptor;
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     *
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args)
    {
        $entity = $args->getEntity();
        $entityManager = $args->getEntityManager();
        $this->processFields($entity, false, $entityManager);
    }

    /**
     * Listen to preflush event
     * Encrypt entities that are inserted into the database
     *
     * @param PreFlushEventArgs $preFlushEventArgs
     */
    public function preFlush(PreFlushEventArgs $preFlushEventArgs)
    {
        $entityManager = $preFlushEventArgs->getEntityManager();
        $unitOfWork = $entityManager->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $entityMap) {
            foreach ($entityMap as $entity) {
                $this->processFields($entity, true, $entityManager);
            }
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities that after inserted into the database
     *
     * @param PostFlushEventArgs $postFlushEventArgs
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs)
    {
        $entityManager = $postFlushEventArgs->getEntityManager();
        $unitOfWork = $entityManager->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $entityMap) {
            foreach ($entityMap as $entity) {
                $this->processFields($entity, false, $entityManager);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents()
    {
        return array(
            Events::postLoad,
            Events::preFlush,
            Events::postFlush,
        );
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object $entity doctrine entity
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     *
     * @throws \RuntimeException
     *
     * @return object|null
     */
    public function processFields($entity, $isEncryptOperation, $entityManager)
    {
        if (!empty($this->encryptor)) {
            // Check which operation to be used
            $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';

            // Get the real class, we don't want to use the proxy classes
            if (strstr(get_class($entity), 'Proxies')) {
                $realClass = ClassUtils::getClass($entity);
            } else {
                $realClass = get_class($entity);
            }

            // Get ReflectionClass of our entity
            $properties = $this->getClassProperties($realClass);

            // Foreach property in the reflection class
            foreach ($properties as $refProperty) {
                if ($this->annReader->getPropertyAnnotation($refProperty, 'Doctrine\ORM\Mapping\Embedded')) {
                    $this->handleEmbeddedAnnotation($entity, $refProperty, $isEncryptOperation, $entityManager);
                    continue;
                }

                /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
                if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {
                    $pac = PropertyAccess::createPropertyAccessor();
                    $value = $pac->getValue($entity, $refProperty->getName());
                    if ($encryptorMethod == 'decrypt') {
                        if (!is_null($value) and !empty($value)) {
                            if (substr($value, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
                                $meta = $entityManager->getClassMetadata($realClass);
                                $identifier = $meta->getSingleIdentifierFieldName();
                                $identifierValue = $pac->getValue($entity, $identifier);
                                if (!isset($this->propertyCache[$realClass])) {
                                    $this->propertyCache[$realClass] = [];
                                }
                                if (!isset($this->propertyCache[$realClass][$identifierValue])) {
                                    $this->propertyCache[$realClass][$identifierValue] = [];
                                }
                                $currentPropValue = $this->encryptor->decrypt(substr($value, 0, -5));
                                $this->propertyCache[$realClass][$identifierValue][$refProperty->getName()] = [$value, $currentPropValue];
                                $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                            }
                        }
                    } else {
                        if (!is_null($value) and !empty($value)) {
                            if (substr($value, -strlen(self::ENCRYPTION_MARKER)) != self::ENCRYPTION_MARKER) {
                                $meta = $entityManager->getClassMetadata($realClass);
                                $identifier = $meta->getSingleIdentifierFieldName();
                                $identifierValue = $pac->getValue($entity, $identifier);
                                if (isset($this->propertyCache[$realClass])
                                    && isset($this->propertyCache[$realClass][$identifierValue])
                                    && isset($this->propertyCache[$realClass][$identifierValue][$refProperty->getName()])) {
                                    if ($this->propertyCache[$realClass][$identifierValue][$refProperty->getName()][1] === $value) {
                                        $currentPropValue = $this->propertyCache[$realClass][$identifierValue][$refProperty->getName()][0];
                                    } else {
                                        $currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                    }
                                    unset($this->propertyCache[$realClass][$identifierValue][$refProperty->getName()]);
                                } else {
                                    $currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                }
                                $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                            }
                        }
                    }
                }
            }

            return $entity;
        }

        return $entity;
    }

    private function handleEmbeddedAnnotation($entity, $embeddedProperty, $isEncryptOperation, $entityManager)
    {
        $propName = $embeddedProperty->getName();

        $pac = PropertyAccess::createPropertyAccessor();

        $embeddedEntity = $pac->getValue($entity, $propName);

        if ($embeddedEntity) {
            $this->processFields($embeddedEntity, $isEncryptOperation, $entityManager);
        }
    }

    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return array
     */
    private function getClassProperties($className)
    {
        $reflectionClass = new ReflectionClass($className);
        $properties      = $reflectionClass->getProperties();
        $propertiesArray = array();

        foreach ($properties as $property) {
            $propertyName = $property->getName();
            $propertiesArray[$propertyName] = $property;
        }

        if ($parentClass = $reflectionClass->getParentClass()) {
            $parentPropertiesArray = $this->getClassProperties($parentClass->getName());
            if (count($parentPropertiesArray) > 0) {
                $propertiesArray = array_merge($parentPropertiesArray, $propertiesArray);
            }
        }

        return $propertiesArray;
    }
}
