package com.example.app.app.rental.domain.dto;

import com.example.app.app.customer.domain.dto.CustomerDto;
import com.example.app.app.payment.domain.dto.PaymentDto;
import com.example.app.app.staff.domain.dto.StaffDto;
import com.example.app.app.store.domain.dto.InventoryDto;
import com.example.app.common.constant.HalRelation;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.google.common.base.Objects;
import lombok.*;
import lombok.experimental.FieldNameConstants;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.hateoas.server.core.Relation;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Collection;

public class RentalDto {
    @Getter
    @Setter
    @ToString
    @FieldNameConstants
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Rental {
        @JsonProperty(Fields.rentalId)
        private Integer rentalId;

        @JsonProperty(Fields.rentalDate)
        private LocalDateTime rentalDate;

        @JsonProperty(Fields.inventoryId)
        private Integer inventoryId;

        @JsonProperty(Fields.customerId)
        private Integer customerId;

        @JsonProperty(Fields.returnDate)
        private LocalDateTime returnDate;

        @JsonProperty(Fields.staffId)
        private Integer staffId;

        @JsonProperty(Fields.lastUpdate)
        private LocalDateTime lastUpdate;

        @JsonIgnore
        @JsonProperty(Fields.paymentsByRentalId)
        @ToString.Exclude
        private Collection<PaymentDto.Payment> paymentsByRentalId;

        @JsonIgnore
        @JsonProperty(Fields.inventoryByInventoryId)
        @ToString.Exclude
        private InventoryDto.Inventory inventoryByInventoryId;

        @JsonIgnore
        @JsonProperty(Fields.customerByCustomerId)
        @ToString.Exclude
        private CustomerDto.Customer customerByCustomerId;

        @JsonIgnore
        @JsonProperty(Fields.staffByStaffId)
        @ToString.Exclude
        private StaffDto.Staff staffByStaffId;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Rental that = (Rental) o;
            return Objects.equal(rentalId, that.rentalId)
                    && Objects.equal(rentalDate, that.rentalDate)
                    && Objects.equal(inventoryId, that.inventoryId)
                    && Objects.equal(customerId, that.customerId)
                    && Objects.equal(returnDate, that.returnDate)
                    && Objects.equal(staffId, that.staffId)
                    && Objects.equal(lastUpdate, that.lastUpdate);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(rentalId, rentalDate, inventoryId, customerId, returnDate,
                    staffId, lastUpdate);
        }
    }

    @Getter
    @Setter
    @ToString
    @FieldNameConstants
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RentalRequest implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @JsonProperty(Fields.rentalDate)
        private LocalDateTime rentalDate;

        @JsonProperty(Fields.inventoryId)
        private Integer inventoryId;

        @JsonProperty(Fields.customerId)
        private Integer customerId;

        @JsonProperty(Fields.returnDate)
        private LocalDateTime returnDate;

        @JsonProperty(Fields.staffId)
        private Integer staffId;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RentalRequest that = (RentalRequest) o;
            return Objects.equal(rentalDate, that.rentalDate)
                    && Objects.equal(inventoryId, that.inventoryId)
                    && Objects.equal(customerId, that.customerId)
                    && Objects.equal(returnDate, that.returnDate)
                    && Objects.equal(staffId, that.staffId);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(rentalDate, inventoryId, customerId, returnDate, staffId);
        }
    }

    @Relation(collectionRelation = HalRelation.Fields.rentalList,
            itemRelation = HalRelation.Fields.rental)
    @Getter
    @Setter
    @ToString
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RentalResponse extends RepresentationModel<RentalResponse> implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        @JsonUnwrapped
        private Rental rental;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            if (!super.equals(o)) return false;
            RentalResponse that = (RentalResponse) o;
            return Objects.equal(rental, that.rental);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(super.hashCode(), rental);
        }
    }
}