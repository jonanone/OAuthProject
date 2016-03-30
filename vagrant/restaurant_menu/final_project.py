from flask import Flask, render_template, redirect, url_for, request
from flask import jsonify, flash
from database_helper import db_init
from database_helper import add_restaurant, edit_restaurant, delete_restaurant
from database_helper import add_menu_item, edit_menu_item, delete_menu_item
from database_helper import get_menu_item, get_restaurant
from database_helper import get_restaurants, get_restaurant_items
from database_helper import get_ordered_restaurants

# Initialization
app = Flask(__name__)
session = db_init()


@app.route('/')
@app.route('/restaurants/')
def listRestaurants():
    restaurants = get_restaurants(session)
    return render_template('restaurants.html',
                           restaurants=restaurants)


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def restaurantMenu(restaurant_id):
    restaurant = get_restaurant(session, restaurant_id)
    items = get_restaurant_items(session, restaurant)
    return render_template('menu.html',
                           restaurant=restaurant,
                           items=items)


@app.route('/restaurant/new', methods=['GET', 'POST'])
def newRestaurant():
    if request.method == 'POST':
        new_restaurant = add_restaurant(session,
                                        {'name': request.form['name']})
        flash(new_restaurant.name + ' restaurant created.')
        return redirect(url_for('listRestaurants'))
    else:
        return render_template('newRestaurant.html')


@app.route('/restaurant/<int:restaurant_id>/edit', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    restaurant = get_restaurant(session, restaurant_id)
    if request.method == 'POST':
        edited_restaurant = edit_restaurant(session,
                                            restaurant_id,
                                            request.form)
        flash(edited_restaurant.name + ' successfully edited')
        return redirect(url_for('listRestaurants'))
    else:
        return render_template('editRestaurant.html',
                               restaurant=restaurant)


@app.route('/restaurant/<int:restaurant_id>/delete', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    restaurant = get_restaurant(session, restaurant_id)
    if request.method == 'POST':
        restaurant_deleted = delete_restaurant(session, restaurant_id)
        if restaurant_deleted:
            flash('Restaurant successfully deleted.')
        else:
            print 'That restaurant cannot be deleted. Please, try again later.'
        return redirect(url_for('listRestaurants'))
    else:
        return render_template('deleteRestaurant.html',
                               restaurant=restaurant)


@app.route('/restaurant/<int:restaurant_id>/menu/item/new',
           methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    restaurant = get_restaurant(session, restaurant_id)
    if request.method == 'POST':
        new_item = add_menu_item(session,
                                 restaurant,
                                 request.form)
        flash(new_item.name + ' menu item successfully added.')
        return redirect(url_for('restaurantMenu',
                                restaurant_id=restaurant_id))
    else:
        return render_template('newMenuItem.html',
                               restaurant=restaurant)


@app.route('/restaurant/<int:restaurant_id>/menu/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, item_id):
    menu_item = get_menu_item(session, item_id)
    restaurant = get_restaurant(session, restaurant_id)
    if request.method == 'POST':
        edited_item = edit_menu_item(session, menu_item, request.form)
        flash(edited_item.name + ' successfully edited.')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editMenuItem.html',
                               restaurant=restaurant,
                               item=menu_item)


@app.route('/restaurant/<int:restaurant_id>/menu/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, item_id):
    menu_item = get_menu_item(session, item_id)
    restaurant = get_restaurant(session, restaurant_id)
    if request.method == 'POST':
        item_deleted = delete_menu_item(session, menu_item)
        if item_deleted:
            flash('Item successfully deleted.')
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant.id))
    else:
        return render_template('deleteMenuItem.html',
                               restaurant=restaurant,
                               item=menu_item)


# Restaurant Menu APP API

@app.route('/restaurants/JSON&order_by=<path:ordering_attr>')
def listRestaurantsJSON(ordering_attr):
    restaurants = get_ordered_restaurants(session, ordering_attr)
    if restaurants:
        return jsonify(Restaurants=[
            restaurant.serialize for restaurant in restaurants
            ])
    else:
        return jsonify(Restaurants=restaurants)


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = get_restaurant(session, restaurant_id)
    items = get_restaurant_items(session, restaurant)
    return jsonify(MenuItems=[item.serialize for item in items])


@app.route('/restaurant/<int:restaurant_id>/menu/item/<int:item_id>/JSON')
def restaurantMenuItemJSON(restaurant_id, item_id):
    menu_item = get_menu_item(session, item_id)
    return jsonify(MenuItem=menu_item.serialize)


if __name__ == '__main__':
    app.secret_key = 'SUPER_SECRET_KEY'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
