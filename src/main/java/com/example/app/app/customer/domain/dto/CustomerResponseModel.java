package com.example.app.app.customer.domain.dto;

import com.example.app.common.constant.HalRelation;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.google.common.base.Objects;
import lombok.*;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.hateoas.server.core.Relation;

import java.io.Serial;
import java.io.Serializable;

@Relation(collectionRelation = HalRelation.Fields.customerList,
        itemRelation = HalRelation.Fields.customer)
@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CustomerResponseModel extends RepresentationModel<CustomerResponseModel> implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @JsonUnwrapped
    private CustomerModel customerModel;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CustomerResponseModel that = (CustomerResponseModel) o;
        return Objects.equal(customerModel, that.customerModel);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(super.hashCode(), customerModel);
    }
}