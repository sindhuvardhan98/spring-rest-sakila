package com.example.app.app.location.assembler;

import com.example.app.app.location.controller.LocationController;
import com.example.app.app.location.domain.dto.CityModel;
import com.example.app.app.location.domain.dto.CityResponseModel;
import com.example.app.common.constant.HalRelation;
import org.springframework.hateoas.server.mvc.RepresentationModelAssemblerSupport;
import org.springframework.stereotype.Component;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@Component
public class CityRepresentationModelAssembler extends RepresentationModelAssemblerSupport<CityModel, CityResponseModel> {
    public CityRepresentationModelAssembler() {
        super(LocationController.class, CityResponseModel.class);
    }

    @Override
    @lombok.NonNull
    public CityResponseModel toModel(@lombok.NonNull CityModel entity) {
        var model = instantiateModel(entity);
        model.setCityModel(entity);
        model.add(linkTo(methodOn(LocationController.class).getCity(String.valueOf(entity.getCityId()))).withSelfRel());
        model.add(linkTo(methodOn(LocationController.class).getAddressList()).withRel(HalRelation.Fields.addressList));
        return model;
    }
}