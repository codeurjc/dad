package es.codeurjc.db;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;
import org.springframework.boot.jackson.JacksonComponent;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Sort;

@JacksonComponent
public class PageImplJacksonSerializer extends ValueSerializer<PageImpl<?>> {

	@SuppressWarnings("rawtypes")
	@Override
	public void serialize(PageImpl page, JsonGenerator jsonGenerator, SerializationContext serializationContext)
			throws JacksonException {

		jsonGenerator.writeStartObject();
		jsonGenerator.writePOJOProperty("content", page.getContent());
		jsonGenerator.writeBooleanProperty("first", page.isFirst());
		jsonGenerator.writeBooleanProperty("last", page.isLast());
		jsonGenerator.writeNumberProperty("totalPages", page.getTotalPages());
		jsonGenerator.writeNumberProperty("totalElements", page.getTotalElements());
		jsonGenerator.writeNumberProperty("numberOfElements", page.getNumberOfElements());

		jsonGenerator.writeNumberProperty("size", page.getSize());
		jsonGenerator.writeNumberProperty("number", page.getNumber());

		Sort sort = page.getSort();

		jsonGenerator.writeArrayPropertyStart("sort");

		for (Sort.Order order : sort) {
			jsonGenerator.writeStartObject();
			jsonGenerator.writeStringProperty("property", order.getProperty());
			jsonGenerator.writeStringProperty("direction", order.getDirection().name());
			jsonGenerator.writeBooleanProperty("ignoreCase", order.isIgnoreCase());
			jsonGenerator.writeStringProperty("nullHandling", order.getNullHandling().name());
			jsonGenerator.writeEndObject();
		}

		jsonGenerator.writeEndArray();
		jsonGenerator.writeEndObject();
	}
}