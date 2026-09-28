package com.cloudsec.config;

import com.cloudsec.model.CloudAuditEvent;
import java.util.Map;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.support.serializer.ErrorHandlingDeserializer;
import org.springframework.kafka.support.serializer.JsonDeserializer;
import org.springframework.kafka.support.serializer.JsonSerializer;
import org.springframework.util.backoff.FixedBackOff;

/**
 * Kafka transport for the pipeline: JSON in, JSON out, with poison-pill protection on the consumer.
 */
@Configuration
@EnableKafka
public class KafkaConfig {

    private final KafkaProperties kafkaProperties;
    private final AnalyzerProperties analyzerProperties;

    public KafkaConfig(KafkaProperties kafkaProperties, AnalyzerProperties analyzerProperties) {
        this.kafkaProperties = kafkaProperties;
        this.analyzerProperties = analyzerProperties;
    }

    @Bean
    public NewTopic securityEventsTopic() {
        return TopicBuilder.name(analyzerProperties.eventsTopic())
                .partitions(analyzerProperties.topicPartitions())
                .replicas(analyzerProperties.topicReplicas())
                .build();
    }

    @Bean
    public NewTopic securityAlertsTopic() {
        return TopicBuilder.name(analyzerProperties.alertsTopic())
                .partitions(analyzerProperties.topicPartitions())
                .replicas(analyzerProperties.topicReplicas())
                .build();
    }

    @Bean
    public ProducerFactory<String, Object> producerFactory() {
        Map<String, Object> config = kafkaProperties.buildProducerProperties(null);
        config.put("key.serializer", StringSerializer.class);
        config.put("value.serializer", JsonSerializer.class);
        config.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, false);
        return new DefaultKafkaProducerFactory<>(config);
    }

    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory<String, Object> producerFactory) {
        return new KafkaTemplate<>(producerFactory);
    }

    @Bean
    public ConsumerFactory<String, CloudAuditEvent> auditEventConsumerFactory() {
        Map<String, Object> config = kafkaProperties.buildConsumerProperties(null);
        config.put("key.deserializer", StringDeserializer.class);
        // A malformed record is turned into a null payload rather than killing the container.
        config.put("value.deserializer", ErrorHandlingDeserializer.class);
        config.put(ErrorHandlingDeserializer.VALUE_DESERIALIZER_CLASS, JsonDeserializer.class);
        config.put(JsonDeserializer.VALUE_DEFAULT_TYPE, CloudAuditEvent.class.getName());
        config.put(JsonDeserializer.USE_TYPE_INFO_HEADERS, false);
        config.put(JsonDeserializer.TRUSTED_PACKAGES, "com.cloudsec.model");
        return new DefaultKafkaConsumerFactory<>(config);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, CloudAuditEvent> kafkaListenerContainerFactory(
            ConsumerFactory<String, CloudAuditEvent> auditEventConsumerFactory,
            ObjectProvider<KafkaTemplate<String, Object>> templateProvider) {
        ConcurrentKafkaListenerContainerFactory<String, CloudAuditEvent> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(auditEventConsumerFactory);
        factory.setConcurrency(analyzerProperties.topicPartitions());
        factory.setBatchListener(true);
        // Two quick retries, then log and move on. Detection is a streaming workload: blocking the
        // partition on one bad record costs more than the record is worth.
        factory.setCommonErrorHandler(new DefaultErrorHandler(new FixedBackOff(500L, 2L)));
        return factory;
    }
}
