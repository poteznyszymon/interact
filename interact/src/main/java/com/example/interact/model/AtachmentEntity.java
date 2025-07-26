package com.example.interact.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "atachments")
@Setter
@Getter
@NoArgsConstructor
public class AtachmentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false)
    private UUID uuid;

    @Column(nullable = false)
    private String url;

    @OneToOne(mappedBy = "avatar")
    private UserEntity user;

    @CreationTimestamp
    private LocalDateTime createdAt;
}
