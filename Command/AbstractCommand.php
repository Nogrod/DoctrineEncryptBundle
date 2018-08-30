<?php
namespace Ambta\DoctrineEncryptBundle\Command;

use Ambta\DoctrineEncryptBundle\Subscribers\DoctrineEncryptSubscriber;
use Doctrine\Common\Annotations\Reader;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Mapping\ClassMetadataInfo;
use Symfony\Component\Console\Command\Command;

/**
 * Base command containing usefull base methods.
 *
 * @author Michael Feinbier <michael@feinbier.net>
 **/
abstract class AbstractCommand extends Command
{
    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @var DoctrineEncryptSubscriber
     */
    protected $subscriber;

    /**
     * @var Reader
     */
    protected $annotationReader;

    /**
     * AbstractCommand constructor.
     *
     * @param EntityManager             $entityManager
     * @param Reader                    $annotationReader
     * @param DoctrineEncryptSubscriber $subscriber
     */
    public function __construct(
        EntityManager $entityManager,
        Reader $annotationReader,
        DoctrineEncryptSubscriber $subscriber
    ) {
        parent::__construct();
        $this->entityManager = $entityManager;
        $this->annotationReader = $annotationReader;
        $this->subscriber = $subscriber;
    }

    /**
     * Get an result iterator over the whole table of an entity.
     *
     * @param string $entityName
     *
     * @return \Doctrine\ORM\Internal\Hydration\IterableResult
     */
    protected function getEntityIterator($entityName)
    {
        $query = $this->entityManager->createQuery(sprintf('SELECT o FROM %s o', $entityName));

        return $query->iterate();
    }

    /**
     * Get the number of rows in an entity-table
     *
     * @param string $entityName
     *
     * @return int
     */
    protected function getTableCount($entityName)
    {
        $query = $this->entityManager->createQuery(sprintf('SELECT COUNT(o) FROM %s o', $entityName));

        return (int) $query->getSingleScalarResult();
    }

    /**
     * Return an array of entity-metadata for all entities
     * that have at least one encrypted property.
     *
     * @return array
     */
    protected function getEncryptionableEntityMetaData()
    {
        $validMetaData = [];
        $metaDataArray = $this->entityManager->getMetadataFactory()->getAllMetadata();

        foreach ($metaDataArray as $entityMetaData)
        {
            if ($entityMetaData instanceof ClassMetadataInfo and $entityMetaData->isMappedSuperclass) {
                continue;
            }

            $properties = $this->getEncryptionableProperties($entityMetaData);
            if (count($properties) == 0) {
                continue;
            }

            $validMetaData[] = $entityMetaData;
        }

        return $validMetaData;
    }

    /**
     * @param $entityMetaData
     *
     * @return array
     */
    protected function getEncryptionableProperties($entityMetaData)
    {
        //Create reflectionClass for each meta data object
        $reflectionClass = new \ReflectionClass($entityMetaData->name);
        $propertyArray = $reflectionClass->getProperties();
        $properties    = [];

        foreach ($propertyArray as $property) {
            if ($this->annotationReader->getPropertyAnnotation($property, 'Ambta\DoctrineEncryptBundle\Configuration\Encrypted')) {
                $properties[] = $property;
            }
        }

        return $properties;
    }
}
