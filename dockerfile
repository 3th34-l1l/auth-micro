FROM node:14

# Create app directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application
COPY . .

# Expose the port on which your app runs
EXPOSE 3000

# Define the command to run your app
CMD ["node", "server.js"]
