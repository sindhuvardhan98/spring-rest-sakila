package com.example.app.app.catalog.assembler;

import com.example.app.app.catalog.controller.ActorController;
import com.example.app.app.catalog.domain.dto.ActorDetailResponseModel;
import com.example.app.app.catalog.domain.dto.ActorDetailsModel;
import com.example.app.common.constant.HalRelation;
import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.server.mvc.RepresentationModelAssemblerSupport;
import org.springframework.stereotype.Component;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@Component
public class ActorDetailsRepresentationModelAssembler extends RepresentationModelAssemblerSupport<ActorDetailsModel, ActorDetailResponseModel> {
    public ActorDetailsRepresentationModelAssembler() {
        super(ActorController.class, ActorDetailResponseModel.class);
    }

    @Override
    @lombok.NonNull
    public ActorDetailResponseModel toModel(@lombok.NonNull ActorDetailsModel entity) {
        var model = instantiateModel(entity);
        model.setActorDetailsModel(entity);
        model.add(linkTo(methodOn(ActorController.class).getActorDetails(String.valueOf(entity.getActorId()))).withSelfRel());
        model.add(linkTo(methodOn(ActorController.class).getActor(String.valueOf(entity.getActorId()))).withRel(HalRelation.Fields.actor));
        model.add(linkTo(methodOn(ActorController.class).getActorList()).withRel(HalRelation.Fields.actorList));
        return model;
    }

    @Override
    @lombok.NonNull
    public CollectionModel<ActorDetailResponseModel> toCollectionModel(@lombok.NonNull Iterable<? extends ActorDetailsModel> entities) {
        return super.toCollectionModel(entities);
    }
}