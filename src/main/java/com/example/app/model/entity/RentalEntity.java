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

@Entity(name = "rental")
@Table(name = "rental", schema = "sakila")
@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RentalEntity implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "rental_id", nullable = false, columnDefinition = "INT")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer rentalId;

    @Basic
    @Column(name = "rental_date", nullable = false, columnDefinition = "DATETIME")
    private LocalDateTime rentalDate;

    @Basic
    @Column(name = "inventory_id", nullable = false, insertable = false, updatable = false, columnDefinition = "MEDIUMINT UNSIGNED")
    private Integer inventoryId;

    @Basic
    @Column(name = "customer_id", nullable = false, insertable = false, updatable = false, columnDefinition = "SMALLINT UNSIGNED")
    private Integer customerId;

    @Basic
    @Column(name = "return_date", nullable = true, columnDefinition = "DATETIME")
    @ColumnDefault("NULL")
    private LocalDateTime returnDate;

    @Basic
    @Column(name = "staff_id", nullable = false, insertable = false, updatable = false, columnDefinition = "TINYINT UNSIGNED")
    private Integer staffId;

    @Basic
    @Column(name = "last_update", nullable = false, columnDefinition = "TIMESTAMP")
    @ColumnDefault("CURRENT_TIMESTAMP")
    @UpdateTimestamp
    private LocalDateTime lastUpdate;

    @OneToMany(mappedBy = "rentalByRentalId", cascade = CascadeType.ALL)
    private Collection<PaymentEntity> paymentsByRentalId;

    @ManyToOne
    @JoinColumn(name = "inventory_id", referencedColumnName = "inventory_id", nullable = false)
    private InventoryEntity inventoryByInventoryId;

    @ManyToOne
    @JoinColumn(name = "customer_id", referencedColumnName = "customer_id", nullable = false)
    private CustomerEntity customerByCustomerId;

    @ManyToOne
    @JoinColumn(name = "staff_id", referencedColumnName = "staff_id", nullable = false)
    private StaffEntity staffByStaffId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RentalEntity that = (RentalEntity) o;
        return Objects.equals(rentalId, that.rentalId)
                && Objects.equals(rentalDate, that.rentalDate)
                && Objects.equals(inventoryId, that.inventoryId)
                && Objects.equals(customerId, that.customerId)
                && Objects.equals(returnDate, that.returnDate)
                && Objects.equals(staffId, that.staffId)
                && Objects.equals(lastUpdate, that.lastUpdate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rentalId, rentalDate, inventoryId, customerId,
                returnDate, staffId, lastUpdate);
    }
}