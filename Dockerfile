# Build stage
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

# Копіюємо тільки файли для завантаження залежностей
COPY build.gradle settings.gradle gradlew ./
COPY gradle gradle

# Завантажуємо залежності (це кешується Docker)
RUN ./gradlew build -x test --refresh-dependencies || true

# Копіюємо весь проєкт
COPY . .

# Збираємо проект без запуску тестів
RUN ./gradlew clean build -x test

# Runtime stage
FROM eclipse-temurin:21-jre
WORKDIR /app

# Копіюємо jar з build stage
COPY --from=build /app/build/libs/*.jar app.jar

# Відкриваємо порт
EXPOSE 8080

# Команда запуску
ENTRYPOINT ["java", "-jar", "app.jar"]
