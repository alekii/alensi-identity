package io.alensi.identity.acl;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "permissions")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "application_id")
    private Application application;

    @Column(nullable = false)
    private String code;

    private String description;

    protected Permission() {
    }

    public Permission(Application application, String code, String description) {
        this.application = application;
        this.code = code;
        this.description = description;
    }

    public Long getId() {
        return id;
    }

    public Application getApplication() {
        return application;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
