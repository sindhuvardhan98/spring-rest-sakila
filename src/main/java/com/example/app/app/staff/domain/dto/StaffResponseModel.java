package com.example.app.app.staff.domain.dto;

import com.example.app.common.constant.HalRelation;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.google.common.base.Objects;
import lombok.*;
import org.springframework.hateoas.RepresentationModel;
import org.springframework.hateoas.server.core.Relation;

import java.io.Serial;
import java.io.Serializable;

@Relation(collectionRelation = HalRelation.Fields.staffList,
        itemRelation = HalRelation.Fields.staff)
@Getter
@Setter
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StaffResponseModel extends RepresentationModel<StaffResponseModel> implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @JsonUnwrapped
    private StaffModel staffModel;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        StaffResponseModel that = (StaffResponseModel) o;
        return Objects.equal(staffModel, that.staffModel);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(super.hashCode(), staffModel);
    }
}