---
description: Learn about the ItemsService in Directus and how to utilize them when building extensions.
contributors: Esther Agbaje
---

# Accessing Items

The `ItemsService` provides access to perform operations on items in a collection. It requires a collection and a schema
to operate.

```js
export default defineEndpoint(async (router, context) => {
  const { services, getSchema } = context;
  const { ItemsService } = services;
  const schema = await getSchema();
  const itemsService = new ItemsService('collection_name', { schema });

  router.get('/', async (req, res) => {
    // Your route handler logic
  });
});
```

## Create an Item

```js
router.post('/', async (req, res) => {
  const data = await itemsService.createOne({
    title: 'Hello world!',
    body: 'This is our first article',
  });

  res.json(data);
});
```

## Get an Item

```js
router.get('/', async (req, res) => {
  const data = await itemsService.readOne('item_id');

  res.json(data);
});
```

## Update an Item

```js
router.patch('/', async (req, res) => {
  const data = await itemsService.updateOne('item_id', {
    title: "An updated title"
  });

  res.json(data);
});
```

## Delete an Item

```js
router.delete('/', async (req, res) => {
  await itemsService.deleteOne('item_id');

  res.json();
});
```

::: tip Explore ItemsService In-depth

Refer to the full list of methods
[in our codebase](https://github.com/directus/directus/blob/main/api/src/services/items.ts).

:::
