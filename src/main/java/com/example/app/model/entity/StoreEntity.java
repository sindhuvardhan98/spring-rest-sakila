package com.example.app.model.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.UpdateTimestamp;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Objects;

@Entity(name = "store")
@Table(name = "store", schema = "sakila")
@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StoreEntity implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "store_id", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer storeId;

    @Basic
    @Column(name = "manager_staff_id", nullable = false, insertable = false, updatable = false, columnDefinition = "TINYINT UNSIGNED")
    private Integer managerStaffId;

    @Basic
    @Column(name = "address_id", nullable = false, insertable = false, updatable = false, columnDefinition = "SMALLINT UNSIGNED")
    private Integer addressId;

    @Basic
    @Column(name = "last_update", nullable = false, columnDefinition = "TIMESTAMP")
    @ColumnDefault("CURRENT_TIMESTAMP")
    @UpdateTimestamp
    private LocalDateTime lastUpdate;

    @OneToMany(mappedBy = "storeByStoreId", cascade = CascadeType.ALL)
    private Collection<CustomerEntity> customersByStoreId;

    @OneToMany(mappedBy = "storeByStoreId", cascade = CascadeType.ALL)
    private Collection<InventoryEntity> inventoriesByStoreId;

    @OneToMany(mappedBy = "storeByStoreId", cascade = CascadeType.ALL)
    private Collection<StaffEntity> staffByStoreId;

    @ManyToOne
    @JoinColumn(name = "manager_staff_id", referencedColumnName = "staff_id", nullable = false)
    private StaffEntity staffByManagerStaffId;

    @ManyToOne
    @JoinColumn(name = "address_id", referencedColumnName = "address_id", nullable = false)
    private AddressEntity addressByAddressId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StoreEntity that = (StoreEntity) o;
        return Objects.equals(storeId, that.storeId)
                && Objects.equals(managerStaffId, that.managerStaffId)
                && Objects.equals(addressId, that.addressId)
                && Objects.equals(lastUpdate, that.lastUpdate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(storeId, managerStaffId, addressId, lastUpdate);
    }
}