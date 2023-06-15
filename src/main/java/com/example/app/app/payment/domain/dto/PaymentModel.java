package com.example.app.app.payment.domain.dto;

import com.example.app.app.customer.domain.dto.CustomerModel;
import com.example.app.app.rental.domain.dto.RentalModel;
import com.example.app.app.staff.domain.dto.StaffModel;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import lombok.*;
import lombok.experimental.FieldNameConstants;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@FieldNameConstants
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentModel {
    @JsonProperty("paymentId")
    private Integer paymentId;

    @JsonProperty("customerId")
    private Integer customerId;

    @JsonProperty("staffId")
    private Integer staffId;

    @JsonProperty("rentalId")
    private Integer rentalId;

    @JsonProperty("amount")
    private BigDecimal amount;

    @JsonProperty("paymentDate")
    private LocalDateTime paymentDate;

    @JsonProperty("lastUpdate")
    private LocalDateTime lastUpdate;

    @JsonIgnore
    @JsonProperty("customerByCustomerId")
    @ToString.Exclude
    private CustomerModel customerByCustomerId;

    @JsonIgnore
    @JsonProperty("staffByStaffId")
    @ToString.Exclude
    private StaffModel staffByStaffId;

    @JsonIgnore
    @JsonProperty("rentalByRentalId")
    @ToString.Exclude
    private RentalModel rentalByRentalId;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PaymentModel that = (PaymentModel) o;
        return Objects.equal(paymentId, that.paymentId)
                && Objects.equal(customerId, that.customerId)
                && Objects.equal(staffId, that.staffId)
                && Objects.equal(rentalId, that.rentalId)
                && Objects.equal(amount, that.amount)
                && Objects.equal(paymentDate, that.paymentDate)
                && Objects.equal(lastUpdate, that.lastUpdate);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(paymentId, customerId, staffId, rentalId, amount,
                paymentDate, lastUpdate);
    }
}